#!/usr/bin/env python3
"""Build script for JASS Prober Agent.

Compiles prober.go to a lightweight Windows PE binary and patches the PE
optional header (Subsystem & OS Version) to 6.0 so the binary can run on
legacy Windows editions (Windows Server 2008, Windows Server 2008 R2, Windows 7,
Windows Server 2012) as well as modern editions (Windows 10, 11, Server 2016-2025).
"""

import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AGENT_DIR.parent.parent
STATIC_DIR = REPO_ROOT / "jass" / "ui" / "static"


def patch_pe_header(file_path: Path, major: int = 6, minor: int = 0) -> None:
    """Patch PE Optional Header Major/Minor Subsystem & OS versions to 6.0."""
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    opt_hdr = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt_hdr)[0]

    if magic not in (0x10B, 0x20B):  # PE32 or PE32+
        raise ValueError(f"Invalid PE magic: {hex(magic)}")

    # MajorOperatingSystemVersion (offset 40)
    # MinorOperatingSystemVersion (offset 42)
    # MajorSubsystemVersion (offset 48)
    # MinorSubsystemVersion (offset 50)
    struct.pack_into("<H", data, opt_hdr + 40, major)
    struct.pack_into("<H", data, opt_hdr + 42, minor)
    struct.pack_into("<H", data, opt_hdr + 48, major)
    struct.pack_into("<H", data, opt_hdr + 50, minor)

    with open(file_path, "wb") as f:
        f.write(data)


def build_binary(arch: str = "amd64", output_name: str = "prober.exe") -> Path:
    """Compile prober.go using Go and patch its PE header."""
    src_file = AGENT_DIR / "prober.go"
    out_file = AGENT_DIR / output_name

    env = os.environ.copy()
    env["GOOS"] = "windows"
    env["GOARCH"] = arch

    # Check for custom GOROOT if available (for RtlGenRandom fallback on Go 1.21+)
    custom_goroot = REPO_ROOT / ".go-custom"
    if custom_goroot.exists():
        env["GOROOT"] = str(custom_goroot)
        go_binary = str(custom_goroot / "bin" / "go")
    else:
        go_binary = shutil.which("go") or "go"

    print(f"[*] Building {output_name} (GOARCH={arch}) using {go_binary}...")
    cmd = [
        go_binary,
        "build",
        "-ldflags=-s -w",
        "-o",
        str(out_file),
        str(src_file),
    ]

    res = subprocess.run(cmd, env=env)
    if res.returncode != 0:
        print(f"[!] Build failed with exit code {res.returncode}", file=sys.stderr)
        sys.exit(res.returncode)

    print(f"[*] Patching PE header to Subsystem Version 6.0 for {output_name}...")
    patch_pe_header(out_file, major=6, minor=0)

    # Copy to static dir so JASS can serve it
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    target_static = STATIC_DIR / output_name
    shutil.copy2(out_file, target_static)
    print(f"[+] Output ready: {out_file} and {target_static}")
    return out_file


def main() -> None:
    print("=" * 60)
    print(" JASS Prober Cross-Compilation & PE Compatibility Tool")
    print("=" * 60)

    # Build 64-bit binary (default for most servers)
    build_binary(arch="amd64", output_name="prober.exe")

    # Build 32-bit binary (fallback for legacy 32-bit Windows 2008)
    build_binary(arch="386", output_name="prober-x86.exe")

    print("\n[✔] All prober binaries built and patched successfully.")


if __name__ == "__main__":
    main()

