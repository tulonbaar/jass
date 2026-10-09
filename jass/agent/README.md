# 🛰️ JASS Prober Agent

The **Prober Agent** (`prober.go`) is a lightweight, ephemeral agent written in Go for Microsoft Windows. It enables deep diagnostic telemetry extraction and remote task execution without requiring heavy agent software installations.

---

## ⚙️ Architecture & Features

- **Single Self-Contained Binary**: Native Go application with no runtime dependencies (.NET, Visual C++ runtimes, or external DLLs are not required).
- **Encrypted Communication**: All communication between JASS and `prober.exe` is encrypted with **AES-256-GCM** using a random pre-shared key (PSK).
- **Ephemeral & Self-Cleaning**: Automatically opens and closes its own Windows Firewall rules (`netsh advfirewall`), and initiates self-destruction (`selfDestruct()`) after its configured Time-to-Live (TTL) expires.
- **Local Diagnostics**: Writes execution logs to `prober-log.log` in the same directory as the executable.
- **Legacy & Modern Windows Support**: Compatible with Windows Server 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025, Windows 7, 8, 10, and 11.

---

## 🔨 Compilation Instructions

Because binary files (`*.exe`) are ignored in git (`.gitignore`), you can compile the agent locally whenever needed.

### Method 1: Automated Build (Recommended)
Use the included cross-compilation script. It compiles both 64-bit (`prober.exe`) and 32-bit (`prober-x86.exe`) binaries and automatically patches the PE subsystem version headers to `6.00` to guarantee compatibility with Windows Server 2008 / 2008 R2:

```bash
# Using Python:
python3 jass/agent/build.py

# Or using Bash:
bash jass/agent/build.sh
```

The compiled binaries will automatically be placed into `jass/ui/static/prober.exe` (where JASS serves them for download) and `jass/agent/prober.exe`.

---

### Method 2: Manual Go Compilation

If you have Go installed:

```bash
# 64-bit Windows (x64):
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o jass/ui/static/prober.exe jass/agent/prober.go

# 32-bit Windows (x86):
GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o jass/ui/static/prober-x86.exe jass/agent/prober.go
```

> [!NOTE]
> **Windows Server 2008 / 2008 R2 / Windows 7 Note:**  
> Go 1.21+ sets `MajorSubsystemVersion = 10` by default in the PE header. When running on Windows Server 2008 R2 (NT 6.1), Windows loader rejects the binary with `ERROR_BAD_EXE_FORMAT` ("Wybrany plik wykonywalny nie jest prawidłową aplikacją tego systemu operacyjnego").  
> Using `python3 jass/agent/build.py` automatically patches the PE header to version `6.0`, ensuring it runs on both legacy and modern Windows systems.

---

## 🚀 Running the Prober Manually

On the destination Windows machine (PowerShell or CMD):

```powershell
.\prober.exe --port 10052 --ttl 3600 --psk "YOUR_PRE_SHARED_KEY"
```

Parameters:
- `--port`: TCP port to listen on (default: `10052`).
- `--ttl`: Time to live in seconds before self-termination (default: `3600`).
- `--psk`: 32-character pre-shared encryption key configured in JASS (required).

A log file named `prober-log.log` will be generated in the same folder as `prober.exe`.

