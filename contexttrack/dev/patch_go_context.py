#!/usr/bin/env python3
"""
NOTE: DO NOT USE THIS SCRIPT.
Keeping it in the repo in case the approach using memory addresses doesn't work.

patch_go_context.py

Script to patch Go stdlib. With this patch, every call to context.Background()
and context.TODO() stores a unique (increasing) integer trace ID.
`context.WithValue` propagates values to all derived contexts, so the trace ID
is reachable from any context in the tree as a struct field.

Example usage in Delve:

    (dlv) print ctx.(*context.valueCtx).val

Note: patched files are written to PATCH_DIR, which is `.go-context-patch`
by default. (Installed Go is never modified.)
To use the patched stdlib, use the `-overlay` build flag.

Usage
─────
1. Run this script once:
       python3 patch_go_context.py

2. Start Delve with the patched stdlib:
       dlv debug --headless --listen=:2345 --api-version=2 \\
           --build-flags="-overlay=$HOME/.go-context-patch/overlay.json" .

3. In the Delve client, read the trace ID directly:
       (dlv) print ctx.(*context.valueCtx).val
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


# - Patch fragments --------------------------------------------------------------------
#
# Each entry is (old_text, new_text).  old_text must appear exactly once in
# context.go; the script aborts if any fragment is not found.

PATCHES = [
    # 1. Add counter and key type after the existing goroutines counter.
    # Note: we need a new type (even if an empty struct) to unquely identify the value
    # attached to context. Unexported type; not accessible by user code.
    (
        # Insert _traceIDCounter and traceKey after existing counters.
        "// goroutines counts the number of goroutines ever created; for testing.\n"
        "var goroutines atomic.Int32",

        "// goroutines counts the number of goroutines ever created; for testing.\n"
        "var goroutines atomic.Int32\n" # unchanged
        "\n"
        "// _traceIDCounter is incremented by every Background() and TODO() call.\n"
        "var _traceIDCounter atomic.Int64\n"
        "\n"
        "// traceKey is the key type used to store trace IDs in root contexts.\n"
        "// Its full name in Delve is 'context.traceKey'.\n"
        "type traceKey struct{}",
    ),

    # 2. Background() wraps the root with a trace ID via WithValue.
    (
        "func Background() Context {\n\treturn backgroundCtx{}\n}",

        "func Background() Context {\n"
        "\treturn WithValue(backgroundCtx{}, traceKey{}, _traceIDCounter.Add(1))\n"
        "}",
    ),

    # 3. TODO() wraps the root with a trace ID via WithValue.
    (
        "func TODO() Context {\n\treturn todoCtx{}\n}",

        "func TODO() Context {\n"
        "\treturn WithValue(todoCtx{}, traceKey{}, _traceIDCounter.Add(1))\n"
        "}",
    ),
]

def find_goroot() -> Path:
    try:
        out = subprocess.run(
            ["go", "env", "GOROOT"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        sys.exit(f"Cannot run 'go env GOROOT': {exc}\n"
                 "Make sure Go is installed and 'go' is on PATH.")
    return Path(out)


def apply_patches(source: str) -> str:
    for old, new in PATCHES:
        count = source.count(old)
        if count == 0:
            # Show a truncated excerpt for easier diagnosis
            excerpt = old.splitlines()[0][:80]
            sys.exit(
                f"Patch target not found in context.go:\n  {excerpt!r}\n"
                "The patch may need updating for this Go version."
            )
        if count > 1:
            excerpt = old.splitlines()[0][:80]
            sys.exit(
                f"Patch target appears {count} times (expected 1):\n  {excerpt!r}"
            )
        source = source.replace(old, new)
    return source


def verify_compiles(patched_file: Path, overlay_path: Path) -> tuple[bool, str]:
    """
      1. gofmt -e — fast syntax check, no stdlib dependencies.
      2. Build minimal program with overlay.  If that fails, check
         whether it also fails *without* the overlay (pre-existing toolchain
         issue).  If the errors are the same, the patch itself is fine.
    """
    # 1. Syntax check
    fmt_result = subprocess.run(
        ["gofmt", "-e", str(patched_file)],
        capture_output=True, text=True,
    )
    if fmt_result.returncode != 0:
        return False, f"gofmt syntax error:\n{fmt_result.stderr}"

    # 2. Build check
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "go.mod").write_text("module _patchtest\ngo 1.21\n")
        (td / "main.go").write_text(
            "package main\n"
            'import "context"\n'
            "func main() {\n"
            "\t_ = context.Background()\n"
            "\t_ = context.TODO()\n"
            "}\n"
        )

        with_overlay = subprocess.run(
            ["go", "build", f"-overlay={overlay_path}", "."],
            capture_output=True, text=True, cwd=tmpdir,
        )
        if with_overlay.returncode == 0:
            return True, ""

        # Build failed — check whether the same error occurs without overlay
        without_overlay = subprocess.run(
            ["go", "build", "."],
            capture_output=True, text=True, cwd=tmpdir,
        )
        if without_overlay.returncode != 0 and without_overlay.stderr == with_overlay.stderr:
            # Pre-existing toolchain issue unrelated to our patch
            return True, (
                f"Note: full build fails due to a pre-existing toolchain issue "
                f"(same error with and without overlay):\n{with_overlay.stderr.strip()}"
            )

        return False, with_overlay.stderr


# - Main --------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Patch Go's context stdlib so Background()/TODO() embed a unique trace ID.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--patch-dir",
        default=str(Path.home() / ".go-context-patch"),
        metavar="DIR",
        help="Directory to write patched context.go and overlay.json "
             "(default: ~/.go-context-patch)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the patch compiles without writing any files",
    )
    args = parser.parse_args()

    patch_dir = Path(args.patch_dir).expanduser()

    # ── Locate stdlib source ──────────────────────────────────────────────
    goroot = find_goroot()
    context_go_orig = goroot / "src" / "context" / "context.go"
    if not context_go_orig.exists():
        sys.exit(f"context.go not found at expected path:\n  {context_go_orig}")

    go_version = subprocess.run(
        ["go", "version"], capture_output=True, text=True,
    ).stdout.strip()

    print(f"Go version: {go_version}")
    print(f"GOROOT:     {goroot}")
    print(f"Source:     {context_go_orig}")

    # - Apply patches --------------------------------------------------------------------
    print("\nApplying patches...")
    source = context_go_orig.read_text()
    patched = apply_patches(source)

    print("Added  _traceIDCounter atomic.Int64 + type traceKey struct{}")
    print("Patched Background() <- WithValue(backgroundCtx{}, traceKey{}, id)")
    print("Patched TODO() <- WithValue(todoCtx{}, traceKey{}, id)")

    if args.check:
        print("\n--check: writing to a temp dir to verify, then discarding...")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_ctx = Path(tmp) / "context.go"
            tmp_overlay = Path(tmp) / "overlay.json"
            tmp_ctx.write_text(patched)
            tmp_overlay.write_text(
                json.dumps({"Replace": {str(context_go_orig): str(tmp_ctx)}}, indent=2)
                + "\n"
            )
            ok, err = verify_compiles(tmp_ctx, tmp_overlay)
        if ok:
            print("  ✓ Patch compiles successfully (dry run — no files written)")
        else:
            print(f"  ✗ Compile error:\n{err}")
            sys.exit(1)
        return

    # - Write output files --------------------------------------------------------------------
    patch_dir.mkdir(parents=True, exist_ok=True)
    patched_context = patch_dir / "context.go"
    overlay_json    = patch_dir / "overlay.json"

    patched_context.write_text(patched)
    print(f"\nWrote patched source: {patched_context}")

    overlay = {"Replace": {str(context_go_orig): str(patched_context)}}
    overlay_json.write_text(json.dumps(overlay, indent=2) + "\n")
    print(f"Wrote overlay: {overlay_json}")

    # - Verify compiles --------------------------------------------------------------------
    print("\nVerifying patch compiles...")
    ok, note = verify_compiles(patched_context, overlay_json)
    if not ok:
        print(f"Compile error:\n{note}")
        sys.exit(1)
    if note:
        print(f"Syntax valid  (warning: {note})")
    else:
        print("Patch compiles")

    print("Patch Done.")


if __name__ == "__main__":
    main()
