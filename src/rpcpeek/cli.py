import argparse
import csv
import io
import json
import sys
from pathlib import Path

from rpcpeek.pe import PEParser
from rpcpeek.ndr import RpcExtractor
from rpcpeek.known_uuids import DB


def analyze_file(filepath: Path) -> dict:
    data = filepath.read_bytes()
    parser = PEParser(data)
    pe_info = parser.parse()
    pe_info.filename = filepath.name

    extractor = RpcExtractor(data, pe_info, parser)
    rpc_imports = {
        dll: [f for f in funcs if f and f.lower().startswith("rpc")]
        for dll, funcs in extractor.extract_imports().items()
    }
    rpc_imports = {k: v for k, v in rpc_imports.items() if v}
    interfaces = extractor.extract_interfaces()

    return {
        "file": pe_info.filename,
        "rpc_imports": rpc_imports,
        "interfaces": interfaces,
    }


def filter_interfaces(result: dict, uuid_filter: str) -> dict:
    filt = uuid_filter.upper()
    filtered = [i for i in result["interfaces"] if filt in i.uuid.upper()]
    return {**result, "interfaces": filtered}


def print_table(result: dict, highlight_method: int = None):
    filename = result["file"]
    interfaces = result["interfaces"]

    if not interfaces:
        print(f"{filename}: no RPC interfaces found")
        return

    for iface in interfaces:
        print(f"\n{filename}")
        syntax_tag = f" [{iface.syntax}]" if iface.syntax != "ndr20" else ""
        name = DB.name(iface.uuid)
        name_tag = f"{name} " if name else ""
        print(f"  Interface: {name_tag}{iface.uuid}{syntax_tag}")
        print(f"  Methods:   {iface.method_count}")
        print()
        print(f"  {'idx':>5}  {'handler RVA':<14}  {'params':>6}")
        print(f"  {'-' * 32}")

        for m in iface.methods:
            marker = ""
            if highlight_method is not None and m.index == highlight_method:
                marker = "  <--"
            print(f"  {m.index:>5}  {m.handler_hex:<14}  {m.param_count:>6}{marker}")


def print_csv(results: list):
    writer = csv.writer(sys.stdout)
    writer.writerow(["file", "uuid", "name", "syntax", "index", "handler_rva", "proc_num", "stack_size", "param_count"])
    for r in results:
        for iface in r["interfaces"]:
            name = DB.name(iface.uuid) or ""
            for m in iface.methods:
                writer.writerow([
                    r["file"], iface.uuid, name, iface.syntax, m.index,
                    m.handler_hex, m.proc_num, m.stack_size, m.param_count,
                ])


def print_summary(results: list):
    print(f"\n{'File':<45} {'Interfaces':>10} {'Methods':>8}")
    print("-" * 68)
    for r in results:
        total_methods = sum(i.method_count for i in r["interfaces"])
        n_iface = len(r["interfaces"])
        if total_methods > 0:
            print(f"{r['file']:<45} {n_iface:>10} {total_methods:>8}")


def print_diff(result_a: dict, result_b: dict):
    def iface_map(result):
        m = {}
        for iface in result["interfaces"]:
            key = (iface.uuid, iface.syntax)
            m[key] = iface
        return m

    map_a = iface_map(result_a)
    map_b = iface_map(result_b)
    keys_a = set(map_a.keys())
    keys_b = set(map_b.keys())

    has_diff = False

    def fmt_key(key):
        name = DB.name(key[0])
        prefix = f"{name} " if name else ""
        return f"{prefix}{key[0]} [{key[1]}]"

    for key in sorted(keys_a - keys_b):
        has_diff = True
        print(f"- {result_a['file']}: {fmt_key(key)} ({map_a[key].method_count} methods)")

    for key in sorted(keys_b - keys_a):
        has_diff = True
        print(f"+ {result_b['file']}: {fmt_key(key)} ({map_b[key].method_count} methods)")

    for key in sorted(keys_a & keys_b):
        a = map_a[key]
        b = map_b[key]
        if a.method_count != b.method_count:
            has_diff = True
            print(f"~ {key[0]} [{key[1]}]: {a.method_count} -> {b.method_count} methods")

        min_methods = min(len(a.methods), len(b.methods))
        for i in range(min_methods):
            if a.methods[i].handler_rva != b.methods[i].handler_rva:
                has_diff = True
                print(f"  method {i}: handler {a.methods[i].handler_hex} -> {b.methods[i].handler_hex}")

        if len(b.methods) > len(a.methods):
            has_diff = True
            for i in range(len(a.methods), len(b.methods)):
                print(f"  + method {i}: handler {b.methods[i].handler_hex}")
        elif len(a.methods) > len(b.methods):
            has_diff = True
            for i in range(len(b.methods), len(a.methods)):
                print(f"  - method {i}: handler {a.methods[i].handler_hex}")

    if not has_diff:
        print("No differences found.")


def main():
    parser = argparse.ArgumentParser(
        description="Extract RPC interfaces and method tables from Windows PE binaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s MpSvc.dll
  %(prog)s --dir Platform/ --summary
  %(prog)s MpSvc.dll --method 161
  %(prog)s MpSvc.dll --format json
  %(prog)s MpSvc.dll --interface C503F532
  %(prog)s --diff old.dll new.dll""",
    )
    parser.add_argument("dll", nargs="?", help="Path to a single DLL to analyze")
    parser.add_argument("--dir", help="Path to a directory of DLLs to scan")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table",
                        help="Output format (default: table)")
    parser.add_argument("--json", action="store_true", help="Output as JSON (alias for --format json)")
    parser.add_argument("--method", type=int, default=None, help="Highlight a specific method index")
    parser.add_argument("--interface", default=None, help="Filter by interface UUID (substring match)")
    parser.add_argument("--summary", action="store_true", help="Only show files that have RPC interfaces")
    parser.add_argument("--diff", nargs=2, metavar="DLL", help="Compare two DLLs")

    args = parser.parse_args()

    if args.json:
        args.format = "json"

    if args.diff:
        try:
            result_a = analyze_file(Path(args.diff[0]))
            result_b = analyze_file(Path(args.diff[1]))
        except Exception as ex:
            print(f"Error: {ex}", file=sys.stderr)
            sys.exit(2)
        print_diff(result_a, result_b)
        sys.exit(0)

    if not args.dll and not args.dir:
        parser.print_help()
        sys.exit(1)

    files = []
    if args.dir:
        dirpath = Path(args.dir)
        files = sorted(dirpath.glob("*.dll"))
        if not files:
            print(f"No DLLs found in {dirpath}", file=sys.stderr)
            sys.exit(2)
    elif args.dll:
        p = Path(args.dll)
        if not p.exists():
            print(f"File not found: {p}", file=sys.stderr)
            sys.exit(2)
        files = [p]

    results = []
    for f in files:
        try:
            result = analyze_file(f)
            if args.interface:
                result = filter_interfaces(result, args.interface)
            results.append(result)
        except Exception as ex:
            if not args.summary:
                print(f"{f.name}: error - {ex}", file=sys.stderr)

    has_interfaces = any(r["interfaces"] for r in results)

    if args.format == "json":
        def serialize(obj):
            if hasattr(obj, "__dict__"):
                d = {k: v for k, v in obj.__dict__.items() if v or k in ("index", "handler_rva")}
                if "uuid" in d:
                    name = DB.name(d["uuid"])
                    if name:
                        d["name"] = name
                return d
            return obj
        print(json.dumps(results, indent=2, default=serialize))
    elif args.format == "csv":
        print_csv(results)
    elif args.summary:
        print_summary(results)
    else:
        for r in results:
            print_table(r, highlight_method=args.method)

    if not has_interfaces:
        sys.exit(1)
