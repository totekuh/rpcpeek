# rpcpeek

Extract RPC interface definitions and method tables from Windows PE binaries.

Parses NDR dispatch tables from DLLs to enumerate RPC interfaces, method counts, and per-method handler addresses. No symbols or Ghidra needed — reads the structures that `RpcServerRegisterIfEx` bakes into the binary.

## Install

```bash
pip install -e .
```

## Usage

```bash
rpcpeek MpSvc.dll
rpcpeek MpSvc.dll --json
rpcpeek MpSvc.dll --method 161
rpcpeek --dir Platform/ --summary
```
