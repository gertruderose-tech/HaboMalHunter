#!/usr/bin/env python3
"""
Extract writes to pipe descriptors from an strace text log.
Groups by kernel pipe id (the number inside pipe:[...]) and by writer PID.

Usage: python3 scripts/extract_pipe_writes.py /path/to/strace.log -o outdir

Produces files: outdir/pipe_<id>_pid<writer>.bin and a summary printed to stdout.
"""
import argparse
import os
import re
import ast

# Example line:
# 42976 14:34:00.812583 write(1<pipe:[429720]>, "0\n", 2) = 2
WRITE_PIPE_RE = re.compile(r"^(?P<pid>\d+)\s+[^ ]+\s+write\((?P<fd>\d+)<pipe:\[(?P<pipeid>\d+)\]>.*,\s*(?P<data>\".*?\"|\<\w+\>),\s*(?P<len>\d+)\) = (?P<ret>\d+)")

ELLIPSIS = '...'


def unescape_quoted(s):
    # s includes surrounding quotes, e.g. "0\n" or "\0\360..."
    if not s:
        return b''
    if s.startswith('<') and s.endswith('>'):
        # strace sometimes prints <...> for non-printable buffers; skip
        return b''
    if s[0] == '"' and s[-1] == '"':
        inner = s[1:-1]
    else:
        inner = s
    # remove trailing ellipsis
    if inner.endswith(ELLIPSIS):
        inner = inner[:-3]
    try:
        b = ast.literal_eval('b"' + inner + '"')
        return b
    except Exception:
        try:
            s2 = inner.encode('utf-8').decode('unicode_escape', errors='ignore')
            return s2.encode('latin1', errors='ignore')
        except Exception:
            return b''


def parse_strace(path):
    pipes = {}  # (pipeid, pid) -> bytearray
    with open(path, 'r', errors='replace') as f:
        for line in f:
            m = WRITE_PIPE_RE.search(line)
            if not m:
                # fallback: look for write(...<pipe:[id]>...) pattern
                if 'write(' in line and '<pipe:[' in line:
                    # extract pid at start
                    try:
                        pid = int(line.split()[0])
                    except Exception:
                        pid = None
                    # find pipe id
                    p = re.search(r'<pipe:\[(\d+)\]>', line)
                    if not p:
                        continue
                    pipeid = int(p.group(1))
                    # find quoted data
                    q = re.search(r',\s*(\".*?\"|<[^>]+>),\s*\d+\) = \d+', line)
                    if not q:
                        continue
                    dataq = q.group(1)
                    b = unescape_quoted(dataq)
                    key = (pipeid, pid)
                    pipes.setdefault(key, bytearray()).extend(b)
                continue
            pid = int(m.group('pid'))
            pipeid = int(m.group('pipeid'))
            dataq = m.group('data')
            b = unescape_quoted(dataq)
            key = (pipeid, pid)
            pipes.setdefault(key, bytearray()).extend(b)
    return pipes


def write_results(pipes, outdir):
    os.makedirs(outdir, exist_ok=True)
    summary = []
    for (pipeid, pid), buf in pipes.items():
        fname = f"pipe_{pipeid}_pid{pid if pid is not None else 'unknown'}.bin"
        path = os.path.join(outdir, fname)
        with open(path, 'wb') as o:
            o.write(buf)
        summary.append((path, len(buf)))
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('strace')
    ap.add_argument('-o', '--outdir', default='log/pipe_extracted')
    args = ap.parse_args()

    pipes = parse_strace(args.strace)
    results = write_results(pipes, args.outdir)
    if not results:
        print('No pipe writes found.')
        return
    print('Extracted pipe writes:')
    for p, l in results:
        print(f'- {p}: {l} bytes')

if __name__ == '__main__':
    main()
