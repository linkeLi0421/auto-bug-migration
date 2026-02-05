#!/usr/bin/env python3
"""
Find OSS-Fuzz base-builder image digest by date.

Usage:
    python3 find_base_image_by_date.py 2024-06-15
    python3 find_base_image_by_date.py 2023-01-01 --list-all
"""

import subprocess
import json
import sys
from datetime import datetime

IMAGE = "gcr.io/oss-fuzz-base/base-builder"

def get_all_tags():
    """Get all available tags using crane."""
    result = subprocess.run(
        ["docker", "run", "--rm", "gcr.io/go-containerregistry/crane", "ls", IMAGE],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error listing tags: {result.stderr}", file=sys.stderr)
        return []
    return result.stdout.strip().split('\n')

def get_image_info(tag):
    """Get image digest and creation date for a tag."""
    # Get digest
    result = subprocess.run(
        ["docker", "run", "--rm", "gcr.io/go-containerregistry/crane", "digest", f"{IMAGE}:{tag}"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return None
    digest = result.stdout.strip()

    # Get creation date via config
    result = subprocess.run(
        ["docker", "run", "--rm", "gcr.io/go-containerregistry/crane", "config", f"{IMAGE}@{digest}"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return None

    try:
        config = json.loads(result.stdout)
        created = config.get('created', '')
        if created:
            # Parse ISO format datetime
            created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
            return {
                'tag': tag,
                'digest': digest,
                'created': created_dt,
                'created_str': created_dt.strftime('%Y-%m-%d %H:%M:%S')
            }
    except (json.JSONDecodeError, ValueError):
        pass
    return None

def find_image_by_date(target_date, list_all=False):
    """Find image closest to (but not after) target date."""
    tags = get_all_tags()
    if not tags:
        print("No tags found")
        return

    # Filter to main tags (exclude manifest-* tags)
    main_tags = [t for t in tags if not t.startswith('manifest-') and '-manifest-' not in t]

    print(f"Checking {len(main_tags)} tags...")

    images = []
    for tag in main_tags:
        info = get_image_info(tag)
        if info:
            images.append(info)
            if list_all:
                print(f"  {info['tag']:40} {info['created_str']}  {info['digest']}")

    if not images:
        print("No images found with date info")
        return

    # Sort by date
    images.sort(key=lambda x: x['created'])

    target_dt = datetime.strptime(target_date, '%Y-%m-%d').replace(tzinfo=images[0]['created'].tzinfo)

    # Find closest image before or on target date
    candidates = [img for img in images if img['created'].date() <= target_dt.date()]

    print(f"\n{'='*80}")
    if candidates:
        best = candidates[-1]  # Latest one before target
        print(f"Best match for {target_date}:")
        print(f"  Tag:     {best['tag']}")
        print(f"  Created: {best['created_str']}")
        print(f"  Digest:  {best['digest']}")
        print(f"\nUse in fuzz_helper.py:")
        print(f"  {IMAGE}@{best['digest']}")
    else:
        print(f"No images found before {target_date}")
        print(f"Earliest available: {images[0]['tag']} ({images[0]['created_str']})")

    print(f"\n{'='*80}")
    print("All images sorted by date:")
    for img in images:
        marker = " <--" if candidates and img == candidates[-1] else ""
        print(f"  {img['created_str']}  {img['tag']:40}  {img['digest']}{marker}")

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    target_date = sys.argv[1]
    list_all = '--list-all' in sys.argv

    try:
        datetime.strptime(target_date, '%Y-%m-%d')
    except ValueError:
        print(f"Invalid date format: {target_date}. Use YYYY-MM-DD")
        sys.exit(1)

    find_image_by_date(target_date, list_all)

if __name__ == '__main__':
    main()
