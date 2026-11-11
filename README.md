# rpcpeek

Static RPC interface and method table extractor for Windows PE binaries.

Parses NDR20 and NDR64 dispatch tables from DLLs to enumerate RPC interfaces, method counts, and per-method handler addresses. No symbols, no Ghidra, no execution — reads the structures that `RpcServerRegisterIfEx` bakes into the binary.

Works on any x64 Windows DLL that registers standard MS-RPC interfaces: Defender services, LSASS, Print Spooler, Task Scheduler, and anything else using the RPC runtime.

## Install

```bash
# With pipx (recommended)
make install

# Or from source
pip install .

# For development
make test
```

## Usage

```bash
# Analyze a single DLL
rpcpeek MpSvc.dll

# JSON output
rpcpeek MpSvc.dll --json

# CSV output (pipe to other tools)
rpcpeek MpSvc.dll --format csv

# Highlight a specific method
rpcpeek MpSvc.dll --method 161

# Filter by interface UUID (substring match)
rpcpeek lsasrv.dll --interface 12345778

# Quick scan: which DLLs have RPC interfaces?
rpcpeek --scan C:\Windows\System32\

# Scan a single file
rpcpeek --scan MpSvc.dll

# Detailed directory summary (with header table)
rpcpeek --dir C:\Windows\System32\ --summary

# Compare method tables across two builds
rpcpeek --diff MpSvc_old.dll MpSvc_new.dll
```

## Reading the output

### Table output

```
lsasrv.dll
  Interface: LSARPC 12345778-1234-ABCD-EF00-0123456789AB
  Methods:   154

    idx  handler RVA     params
  --------------------------------
      0  0x98dd0              2
      1  0xd0e40              3
      2  0x111570             5
```

- **Interface** — the RPC interface UUID. Known interfaces (SAMR, LSARPC, EFSRPC, etc.) get a name prefix. Interfaces registered with both NDR20 and NDR64 show up twice, with `[ndr64]` on the second.
- **Methods** — number of RPC methods (procedures) the interface exposes.
- **idx** — method index (proc number in the dispatch table).
- **handler RVA** — relative virtual address of the method's server-side handler function. Load the DLL in a disassembler and go to this address to see the implementation.
- **params** — number of parameters the method accepts.

### JSON output

Each interface includes `uuid`, `method_count`, `syntax` (`ndr20` or `ndr64`), and a `methods` array. Known interfaces get a `name` field. Each method has `index`, `handler_rva`, `proc_num`, `stack_size`, `client_buffer`, `server_buffer`, and `param_count`.

### CSV output

One row per method. Columns: `file`, `uuid`, `name`, `syntax`, `index`, `handler_rva`, `proc_num`, `stack_size`, `param_count`. Good for grep, awk, or loading into a spreadsheet.

### Scan output

```
MpSvc.dll              3 interfaces   297 methods
DefenderAiPlatform.dll 1 interface      6 methods
DsMain.dll             1 interface      8 methods
```

One line per DLL that has RPC interfaces. Deduplicates NDR20/NDR64 registrations — a UUID registered in both syntaxes counts as one interface. Accepts a directory or a single file. Combine with `--interface` to filter by UUID substring.

### Diff output

```
- old.dll: C503F532-443A-4C69-8300-CCD1FBDB3839 [ndr20] (238 methods)
+ new.dll: DFSNM 4FC742E0-4A10-11CF-8273-00AA004AE673 [ndr20] (12 methods)
~ C503F532-443A-4C69-8300-CCD1FBDB3839 [ndr20]: 238 -> 240 methods
  method 161: handler 0x16c950 -> 0x16d100
```

- `-` lines: interfaces present only in the first DLL
- `+` lines: interfaces present only in the second DLL
- `~` lines: interfaces in both but with changes (method count, handler RVAs)

### Exit codes

- `0` — success, RPC interfaces found
- `1` — no RPC interfaces found
- `2` — file not found or parse error

## License

MIT
