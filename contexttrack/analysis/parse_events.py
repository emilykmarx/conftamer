#!/usr/bin/env python3
import argparse
from collections import Counter

from event_io import load_events


def parse_events(path: str) -> None:
    file_counts: Counter = Counter()
    source_counts: Counter = Counter()
    frames_searched_counts: Counter = Counter()

    for event in load_events(path):
        if "file" in event:
            file_counts[event["file"]] += 1

        ctx = event.get("context", {})
        if "source" in ctx:
            source_counts[ctx["source"]] += 1

        frames = ctx.get("frames_searched")
        if isinstance(frames, list):
            frames_searched_counts[len(frames)] += 1

    print("=== File counts ===")
    for file, count in file_counts.most_common():
        print(f"  {count:6d}  {file}")

    print("\n=== Context source counts ===")
    for source, count in source_counts.most_common():
        print(f"  {count:6d}  {source}")

    print("\n=== frames_searched length counts ===")
    for length, count in sorted(frames_searched_counts.items()):
        print(f"  length {length:3d}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse and summarize events.jsonl")
    parser.add_argument(
        "path",
        nargs="?",
        default="contexttrack/events/events.jsonl",
        help="Path to events JSONL file",
    )
    args = parser.parse_args()
    parse_events(args.path)


if __name__ == "__main__":
    main()
