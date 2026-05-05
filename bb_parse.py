#!/usr/bin/env python3
"""Helper for bb-pull-project.sh: parse Bitbucket JSON API responses via stdin."""

import sys
import json

def load():
    return json.load(sys.stdin)

def cloud_urls():
    data = load()
    for r in data.get('values', []):
        links = r.get('links', {}).get('clone', [])
        ssh   = next((l['href'] for l in links if l['name'] == 'ssh'),   None)
        https = next((l['href'] for l in links if l['name'] == 'https'), None)
        print(ssh or https or '')

def cloud_next():
    data = load()
    print(data.get('next', ''))

def server_urls():
    data = load()
    for r in data.get('values', []):
        links = r.get('links', {}).get('clone', [])
        ssh   = next((l['href'] for l in links if l['name'] == 'ssh'),  None)
        https = next((l['href'] for l in links if l['name'] == 'http'), None)
        print(ssh or https or '')

def server_islast():
    data = load()
    print('true' if data.get('isLastPage', True) else 'false')

def server_nextstart():
    data = load()
    print(data.get('nextPageStart', 0))

COMMANDS = {
    'cloud-urls':       cloud_urls,
    'cloud-next':       cloud_next,
    'server-urls':      server_urls,
    'server-islast':    server_islast,
    'server-nextstart': server_nextstart,
}

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    fn = COMMANDS.get(cmd)
    if fn is None:
        print(f'Usage: bb_parse.py <{"  |  ".join(COMMANDS)}>', file=sys.stderr)
        sys.exit(1)
    fn()
