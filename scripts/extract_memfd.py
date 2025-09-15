#!/usr/bin/env python3
"""
Simple memfd extractor for strace logs.
Parses memfd_create, write(...) to memfd:NAME, and ftruncate, and reconstructs blobs.

Usage: python3 scripts/extract_memfd.py /path/to/strace.log -o outdir

Notes:
- This is a heuristic parser for strace text output. It handles lines like:
  memfd_create("upx", MFD_EXEC) = 4</memfd:upx>(deleted)
  write(4</memfd:upx>(deleted), "\0\360...", 3299) = 3299
  ftruncate(4</memfd:upx>(deleted), 2019101) = 0

- Reconstructed files will be named by the memfd fd and optional name (e.g. fd4_upx.bin).
"""
import argparse
import os
import re
import ast

MEMFD_RE = re.compile(r"memfd_create\(\"(?P<name>[^\"]*)\".*\) = (?P<fd>\d+).*</memfd:(?P<tag>[^>]*)>\(?deleted\)?")
FDTAG_RE = re.compile(r"(?P<fd>\d+)</memfd:(?P<tag>[^>]+)>")
WRITE_RE = re.compile(r"write\((?P<fd>\d+)</memfd:[^>]+>.*?,\s*(?P<data>\".*\"),\s*(?P<len>\d+)\) = (?P<ret>\d+)")


# pattern to capture escaped string contents between quotes; strace prints escapes like \0\360\377...
ESCAPED_STR_RE = re.compile(r'"(.*)"', re.DOTALL)

FTRUNC_RE = re.compile(r"ftruncate\((?P<fd>\d+)</memfd:[^>]+>.*?,\s*(?P<size>\d+)\) = (?P<ret>\d+)")

# Some strace prints the binary data with "..." and ellipsis if it's long; if so, we cannot recover entire blob.
ELLIPSIS = '...'


def unescape_strace_bytes(s):
    # s is the quoted substring including surrounding quotes, e.g. "\0\360..."
    # Remove surrounding quotes if present
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        inner = s[1:-1]
    else:
        inner = s

    # Truncated data in strace often ends with '...'; keep the prefix before the ellipsis
    if inner.endswith('...'):
        inner = inner[:-3]

    try:
        # construct a Python bytes literal and evaluate
        b = ast.literal_eval('b"' + inner + '"')
        return b
    except Exception:
        # fallback best-effort
        try:
            s2 = inner.encode('utf-8').decode('unicode_escape', errors='ignore')
            return s2.encode('latin1', errors='ignore')
        except Exception:
            return b''


def parse_strace(path):
    memfds = {}  # fd -> {name, tag, writes: [(offset, bytes)], ftruncate: size}

    # We'll attempt to track write sequence; strace doesn't print offsets, so we'll append in order.
    with open(path, 'r', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            # memfd_create
            m = MEMFD_RE.search(line)
            if m:
                fd = int(m.group('fd'))
                name = m.group('name')
                tag = m.group('tag')
                memfds[fd] = {'name': name or tag, 'tag': tag, 'writes': [], 'ftruncate': None}
                continue

            # ftruncate
            m = FTRUNC_RE.search(line)
            if m:
                fd = int(m.group('fd'))
                size = int(m.group('size'))
                if fd in memfds:
                    memfds[fd]['ftruncate'] = size
                continue

            # write to memfd: try to capture via regex first
            m = WRITE_RE.search(line)
            if m:
                fd = int(m.group('fd'))
                data_quoted = m.group('data')
                b = unescape_strace_bytes(data_quoted)
                if fd in memfds:
                    memfds[fd]['writes'].append(b)
                continue

            # fallback: manual parse for lines like:
            # write(3</memfd:upX>(deleted), "..."..., 3299) = 3299
            if 'write(' in line and '</memfd:' in line:
                # get fd after 'write('
                mfd = re.search(r'write\((\d+)', line)
                if not mfd:
                    continue
                fd = int(mfd.group(1))
                # find first '"' after the fd position
                fd_pos = line.find(mfd.group(0))
                quote_pos = line.find('"', fd_pos)
                if quote_pos == -1:
                    continue
                end_quote = line.find('"', quote_pos+1)
                if end_quote == -1:
                    # truncated or unusual; take to the comma
                    comma_pos = line.find(',', quote_pos)
                    if comma_pos == -1:
                        continue
                    inner = line[quote_pos+1:comma_pos]
                else:
                    inner = line[quote_pos+1:end_quote]
                b = unescape_strace_bytes('"' + inner + '"')
                if fd in memfds:
                    memfds[fd]['writes'].append(b)
                continue

    return memfds


def write_blobs(memfds, outdir):
    os.makedirs(outdir, exist_ok=True)
    results = []
    for fd, info in memfds.items():
        name = info['name']
        parts = info['writes']
        if not parts:
            continue
        outname = f"fd{fd}_{name}.bin"
        outpath = os.path.join(outdir, outname)
        with open(outpath, 'wb') as o:
            for part in parts:
                o.write(part)
        size = os.path.getsize(outpath)
        results.append((outpath, size, info.get('ftruncate')))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('strace', help='path to strace text file')
    ap.add_argument('-o', '--outdir', default='log/memfd_extracted', help='output directory')
    args = ap.parse_args()

    memfds = parse_strace(args.strace)
    results = write_blobs(memfds, args.outdir)
    if not results:
        print('No memfd writes found or unable to reconstruct data.')
        return
    print('Reconstructed memfd blobs:')
    for p,size,ftr in results:
        print(f"- {p}: {size} bytes (ftruncate={ftr})")

if __name__ == '__main__':
    main()
