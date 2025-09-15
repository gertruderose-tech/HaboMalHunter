
## Overview

This repository contains notes and guidance for a locally-observed, unknown program named `requirement`.

Observed characteristics (reported by the user):
- `requirement` is a single file executable in the working directory (`./requirement`).
- The program runs without root privileges.
- It appears to load into memory and self-extract an embedded `bash` script (or payload) into memory and then self-delete its on-disk copy.
- The behavior suggests the binary unpacks content into memory and may clean up traces on disk.

This README documents defensive, forensic, and analysis-oriented steps you can take when encountering such a binary. It intentionally focuses on safe, lawful procedures and does not provide guidance for evasion or persistence techniques.

## Evidence collection (forensic capture)

Goal: Collect enough evidence to analyze the binary and the running process while preserving integrity for later review.

Safe, commonly used collection steps (do these with permission and on machines you control):

- Identify the process and gather basic metadata:

```
ps aux | grep -F "./requirement" -n
pgrep -a requirement || pgrep -a "requirement"
```

- Note the PID(s) and capture process metadata:

```
PID=<the pid>
cat /proc/$PID/cmdline
readlink -f /proc/$PID/exe
ls -l /proc/$PID/fd
lsof -p $PID
```

- Copy the original on-disk executable if still present (preserve timestamps):

```
cp -a ./requirement ./evidence/requirement.bin
sha256sum ./evidence/requirement.bin > ./evidence/requirement.bin.sha256
```

- If the executable has already self-deleted from disk, you can still try to recover its image from the running process. Preferred, minimally invasive method: create a core dump.

Use gcore (part of gdb) to create a core image of the running process:

```
mkdir -p ./evidence
gcore -o ./evidence/core.$PID $PID
sha256sum ./evidence/core.$PID.* > ./evidence/core.$PID.sha256
```

gcore produces a snapshot of the process memory which can be used to extract embedded files or scripts.

- Alternative: copy /proc/$PID/exe if it points to an inode (works if the file hasn't been fully unlinked):

```
cp /proc/$PID/exe ./evidence/requirement.fromproc
sha256sum ./evidence/requirement.fromproc > ./evidence/requirement.fromproc.sha256
```

Notes and cautions:
- Avoid writing to the execution directory of the running program.
- Some actions (like attaching debuggers) may change process behavior; prefer passive collection if you need to preserve exact runtime behavior.

## Memory analysis — extracting an embedded script

Once you have a core dump or a copy of the in-memory image, you can search for readable text or shebang lines. Common quick checks:

```
strings ./evidence/core.$PID.* | egrep -i "^#!|bash|/bin/sh|/usr/bin/env"
strings ./evidence/requirement.bin | egrep -i "^#!|bash|/bin/sh|/usr/bin/env"
```

If the binary packed a script in memory, a `strings` scan often finds the plaintext script or parts of it. For more targeted extraction, use tools such as: `binwalk`, `foremost`, `scalpel`, or manual carving based on offsets seen in `strings` output.

For scripted extraction workflows, load the core into a debugger or an analysis tool (radare2, Ghidra, rizin) which can inspect mapped regions and extract ranges of memory as files.

## Static analysis of the binary

Basic static checks (non-exhaustive):

- Identify file type

```
file ./evidence/requirement.bin
readelf -h ./evidence/requirement.bin
```

- Compute hashes and record them for detection and IOC creation:

```
sha1sum sha256sum ./evidence/requirement.bin
```

- Strings and initial triage:

```
strings -a -n 8 ./evidence/requirement.bin | less
```

- Use disassembly/analysis tools for deeper inspection:
	- radare2 / rizin: quick triage, inspect segments, dump sections
	- ghidra / IDA Pro / Binary Ninja: decompile and inspect logic
	- ldd to check for dynamic linking (static binaries typically do not show external shared libs)

If the binary is statically linked or packed, look for 3rd-party packer stubs. Tools like `upx -d` can detect and unpack common packers, but many custom packers exist.
