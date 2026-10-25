#!/usr/bin/env python3
"""Helper for fj-pull-org.sh: parse Forgejo JSON API responses via stdin."""

import json
import sys


def load():
    return json.load(sys.stdin)

def repos():
    data = load()
    if not isinstance(data, list):
        # Forgejo answers errors with an object: {"message": ..., "url": ...}
        msg = data.get('message', '') if isinstance(data, dict) else ''
        print(f'Unexpected API response (no repository list): {msg}', file=sys.stderr)
        sys.exit(1)
    return data

def urls():
    for r in repos():
        print(r.get('clone_url') or '')

def count():
    print(len(repos()))

COMMANDS = {
    'urls':  urls,
    'count': count,
}

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    fn = COMMANDS.get(cmd)
    if fn is None:
        print(f'Usage: fj_parse.py <{"  |  ".join(COMMANDS)}>', file=sys.stderr)
        sys.exit(1)
    fn()
