import csv
import io
import json
import subprocess
import sys

import pytest

from rpcpeek.cli import main, print_table, print_summary, print_scan, print_csv, print_diff, filter_interfaces, analyze_file
from rpcpeek.models import RpcInterface, RpcMethod


class TestPrintTable:
    def test_no_interfaces(self, capsys):
        result = {"file": "empty.dll", "interfaces": []}
        print_table(result)
        captured = capsys.readouterr()
        assert "no RPC interfaces found" in captured.out

    def test_with_methods(self, capsys):
        iface = RpcInterface(uuid="TEST-UUID", method_count=1)
        iface.methods.append(RpcMethod(index=0, handler_rva=0x1000, param_count=3))
        result = {"file": "test.dll", "interfaces": [iface]}
        print_table(result)
        captured = capsys.readouterr()
        assert "TEST-UUID" in captured.out
        assert "0x1000" in captured.out

    def test_highlight_method(self, capsys):
        iface = RpcInterface(uuid="TEST-UUID", method_count=2)
        iface.methods.append(RpcMethod(index=0, handler_rva=0x1000, param_count=1))
        iface.methods.append(RpcMethod(index=1, handler_rva=0x2000, param_count=2))
        result = {"file": "test.dll", "interfaces": [iface]}
        print_table(result, highlight_method=1)
        captured = capsys.readouterr()
        assert "<--" in captured.out

    def test_ndr64_tag(self, capsys):
        iface = RpcInterface(uuid="TEST-UUID", method_count=1, syntax="ndr64")
        iface.methods.append(RpcMethod(index=0, handler_rva=0x1000, param_count=1))
        result = {"file": "test.dll", "interfaces": [iface]}
        print_table(result)
        captured = capsys.readouterr()
        assert "[ndr64]" in captured.out

    def test_ndr20_no_tag(self, capsys):
        iface = RpcInterface(uuid="TEST-UUID", method_count=1, syntax="ndr20")
        iface.methods.append(RpcMethod(index=0, handler_rva=0x1000, param_count=1))
        result = {"file": "test.dll", "interfaces": [iface]}
        print_table(result)
        captured = capsys.readouterr()
        assert "[ndr20]" not in captured.out


class TestPrintCSV:
    def test_csv_header(self, capsys):
        results = [{"file": "test.dll", "interfaces": []}]
        print_csv(results)
        captured = capsys.readouterr()
        assert "file,uuid,name,syntax,index,handler_rva,proc_num,stack_size,param_count" in captured.out

    def test_csv_data_rows(self, capsys):
        iface = RpcInterface(uuid="TEST-UUID", method_count=1, syntax="ndr20")
        iface.methods.append(RpcMethod(index=0, handler_rva=0x1000, proc_num=0, stack_size=16, param_count=3))
        results = [{"file": "test.dll", "interfaces": [iface]}]
        print_csv(results)
        captured = capsys.readouterr()
        reader = csv.reader(io.StringIO(captured.out))
        rows = list(reader)
        assert len(rows) == 2
        assert rows[1][0] == "test.dll"
        assert rows[1][1] == "TEST-UUID"


class TestFilterInterfaces:
    def test_filter_match(self):
        iface_a = RpcInterface(uuid="AAAA-BBBB", method_count=1)
        iface_b = RpcInterface(uuid="CCCC-DDDD", method_count=1)
        result = {"file": "test.dll", "interfaces": [iface_a, iface_b]}
        filtered = filter_interfaces(result, "AAAA")
        assert len(filtered["interfaces"]) == 1
        assert filtered["interfaces"][0].uuid == "AAAA-BBBB"

    def test_filter_case_insensitive(self):
        iface = RpcInterface(uuid="AAAA-BBBB", method_count=1)
        result = {"file": "test.dll", "interfaces": [iface]}
        filtered = filter_interfaces(result, "aaaa")
        assert len(filtered["interfaces"]) == 1

    def test_filter_no_match(self):
        iface = RpcInterface(uuid="AAAA-BBBB", method_count=1)
        result = {"file": "test.dll", "interfaces": [iface]}
        filtered = filter_interfaces(result, "ZZZZ")
        assert len(filtered["interfaces"]) == 0


class TestTriageScore:
    def test_struct_scores_higher(self):
        from rpcpeek.cli import _triage_score
        m_struct = RpcMethod(index=0, handler_rva=0x1000, param_types=["struct*"], auth_check="yes")
        m_int = RpcMethod(index=1, handler_rva=0x2000, param_types=["int"], auth_check="yes")
        assert _triage_score(m_struct) > _triage_score(m_int)

    def test_no_auth_scores_higher(self):
        from rpcpeek.cli import _triage_score
        m_no = RpcMethod(index=0, handler_rva=0x1000, param_types=["int"], auth_check="none")
        m_yes = RpcMethod(index=1, handler_rva=0x2000, param_types=["int"], auth_check="yes")
        assert _triage_score(m_no) > _triage_score(m_yes)

    def test_struct_plus_no_auth_highest(self):
        from rpcpeek.cli import _triage_score
        m_best = RpcMethod(index=0, handler_rva=0x1000, param_types=["struct*", "wstr*"], auth_check="none")
        m_mid = RpcMethod(index=1, handler_rva=0x2000, param_types=["struct*"], auth_check="yes")
        m_low = RpcMethod(index=2, handler_rva=0x3000, param_types=["int"], auth_check="yes")
        assert _triage_score(m_best) > _triage_score(m_mid) > _triage_score(m_low)

    def test_empty_params_zero_auth_yes(self):
        from rpcpeek.cli import _triage_score
        m = RpcMethod(index=0, handler_rva=0x1000, param_types=[], auth_check="yes")
        assert _triage_score(m) == 0

    def test_array_scores_one(self):
        from rpcpeek.cli import _triage_score
        m = RpcMethod(index=0, handler_rva=0x1000, param_types=["array*"], auth_check="yes")
        assert _triage_score(m) == 1


class TestPrintTriage:
    def test_basic_output(self, capsys):
        from rpcpeek.cli import print_triage
        iface = RpcInterface(uuid="TEST-UUID", method_count=2, syntax="ndr20")
        iface.methods.append(RpcMethod(index=0, handler_rva=0x1000, param_types=["int", "struct*"], auth_check="none"))
        iface.methods.append(RpcMethod(index=1, handler_rva=0x2000, param_types=["int"], auth_check="yes"))
        result = {"file": "test.dll", "interfaces": [iface]}
        print_triage(result)
        captured = capsys.readouterr()
        assert "TEST-UUID" in captured.out
        assert "[int, struct*]" in captured.out
        assert "none" in captured.out
        assert "yes" in captured.out

    def test_sorts_interesting_first(self, capsys):
        from rpcpeek.cli import print_triage
        iface = RpcInterface(uuid="TEST-UUID", method_count=2, syntax="ndr20")
        iface.methods.append(RpcMethod(index=0, handler_rva=0x1000, param_types=["int"], auth_check="yes"))
        iface.methods.append(RpcMethod(index=1, handler_rva=0x2000, param_types=["struct*", "wstr*"], auth_check="none"))
        result = {"file": "test.dll", "interfaces": [iface]}
        print_triage(result)
        captured = capsys.readouterr()
        lines = [l.strip() for l in captured.out.strip().split("\n") if l.strip().startswith(("0", "1"))]
        assert lines[0].startswith("1")

    def test_skips_ndr64(self, capsys):
        from rpcpeek.cli import print_triage
        ndr20 = RpcInterface(uuid="TEST-UUID", method_count=1, syntax="ndr20")
        ndr20.methods.append(RpcMethod(index=0, handler_rva=0x1000, param_types=["int"], auth_check="none"))
        ndr64 = RpcInterface(uuid="TEST-UUID", method_count=1, syntax="ndr64")
        ndr64.methods.append(RpcMethod(index=0, handler_rva=0x1000))
        result = {"file": "test.dll", "interfaces": [ndr20, ndr64]}
        print_triage(result)
        captured = capsys.readouterr()
        assert captured.out.count("Interface:") == 1

    def test_no_interfaces(self, capsys):
        from rpcpeek.cli import print_triage
        result = {"file": "empty.dll", "interfaces": []}
        print_triage(result)
        captured = capsys.readouterr()
        assert "no RPC interfaces found" in captured.out

    def test_empty_param_types(self, capsys):
        from rpcpeek.cli import print_triage
        iface = RpcInterface(uuid="TEST-UUID", method_count=1, syntax="ndr20")
        iface.methods.append(RpcMethod(index=0, handler_rva=0x1000, param_types=[], auth_check="none"))
        result = {"file": "test.dll", "interfaces": [iface]}
        print_triage(result)
        captured = capsys.readouterr()
        assert "[]" in captured.out

    def test_auth_unknown_shows_question(self, capsys):
        from rpcpeek.cli import print_triage
        iface = RpcInterface(uuid="TEST-UUID", method_count=1, syntax="ndr20")
        iface.methods.append(RpcMethod(index=0, handler_rva=0x1000, param_types=["int"]))
        result = {"file": "test.dll", "interfaces": [iface]}
        print_triage(result)
        captured = capsys.readouterr()
        assert "?" in captured.out


class TestPrintDiff:
    def test_no_differences(self, capsys):
        iface = RpcInterface(uuid="TEST", method_count=1, syntax="ndr20")
        iface.methods.append(RpcMethod(index=0, handler_rva=0x1000))
        result = {"file": "a.dll", "interfaces": [iface]}
        print_diff(result, result)
        captured = capsys.readouterr()
        assert "No differences found" in captured.out

    def test_added_interface(self, capsys):
        result_a = {"file": "a.dll", "interfaces": []}
        iface_b = RpcInterface(uuid="NEW-UUID", method_count=1, syntax="ndr20")
        result_b = {"file": "b.dll", "interfaces": [iface_b]}
        print_diff(result_a, result_b)
        captured = capsys.readouterr()
        assert "+ b.dll: NEW-UUID" in captured.out

    def test_removed_interface(self, capsys):
        iface_a = RpcInterface(uuid="OLD-UUID", method_count=1, syntax="ndr20")
        result_a = {"file": "a.dll", "interfaces": [iface_a]}
        result_b = {"file": "b.dll", "interfaces": []}
        print_diff(result_a, result_b)
        captured = capsys.readouterr()
        assert "- a.dll: OLD-UUID" in captured.out

    def test_changed_method_count(self, capsys):
        iface_a = RpcInterface(uuid="TEST", method_count=5, syntax="ndr20")
        iface_b = RpcInterface(uuid="TEST", method_count=10, syntax="ndr20")
        result_a = {"file": "a.dll", "interfaces": [iface_a]}
        result_b = {"file": "b.dll", "interfaces": [iface_b]}
        print_diff(result_a, result_b)
        captured = capsys.readouterr()
        assert "5 -> 10 methods" in captured.out

    def test_changed_handler_rva(self, capsys):
        iface_a = RpcInterface(uuid="TEST", method_count=1, syntax="ndr20")
        iface_a.methods.append(RpcMethod(index=0, handler_rva=0x1000))
        iface_b = RpcInterface(uuid="TEST", method_count=1, syntax="ndr20")
        iface_b.methods.append(RpcMethod(index=0, handler_rva=0x2000))
        result_a = {"file": "a.dll", "interfaces": [iface_a]}
        result_b = {"file": "b.dll", "interfaces": [iface_b]}
        print_diff(result_a, result_b)
        captured = capsys.readouterr()
        assert "0x1000" in captured.out
        assert "0x2000" in captured.out

    def test_added_methods(self, capsys):
        iface_a = RpcInterface(uuid="TEST", method_count=1, syntax="ndr20")
        iface_a.methods.append(RpcMethod(index=0, handler_rva=0x1000))
        iface_b = RpcInterface(uuid="TEST", method_count=2, syntax="ndr20")
        iface_b.methods.append(RpcMethod(index=0, handler_rva=0x1000))
        iface_b.methods.append(RpcMethod(index=1, handler_rva=0x2000))
        result_a = {"file": "a.dll", "interfaces": [iface_a]}
        result_b = {"file": "b.dll", "interfaces": [iface_b]}
        print_diff(result_a, result_b)
        captured = capsys.readouterr()
        assert "+ method 1" in captured.out

    def test_removed_methods(self, capsys):
        iface_a = RpcInterface(uuid="TEST", method_count=2, syntax="ndr20")
        iface_a.methods.append(RpcMethod(index=0, handler_rva=0x1000))
        iface_a.methods.append(RpcMethod(index=1, handler_rva=0x2000))
        iface_b = RpcInterface(uuid="TEST", method_count=1, syntax="ndr20")
        iface_b.methods.append(RpcMethod(index=0, handler_rva=0x1000))
        result_a = {"file": "a.dll", "interfaces": [iface_a]}
        result_b = {"file": "b.dll", "interfaces": [iface_b]}
        print_diff(result_a, result_b)
        captured = capsys.readouterr()
        assert "- method 1" in captured.out


class TestPrintScan:
    def test_basic_output(self, capsys):
        iface_a = RpcInterface(uuid="AAAA-1111", method_count=5)
        iface_b = RpcInterface(uuid="BBBB-2222", method_count=10)
        results = [
            {"file": "alpha.dll", "interfaces": [iface_a]},
            {"file": "beta.dll", "interfaces": [iface_b]},
        ]
        print_scan(results)
        captured = capsys.readouterr()
        assert "alpha.dll" in captured.out
        assert "beta.dll" in captured.out
        assert "5" in captured.out
        assert "10" in captured.out

    def test_singular_forms(self, capsys):
        iface = RpcInterface(uuid="AAAA-1111", method_count=1)
        results = [{"file": "one.dll", "interfaces": [iface]}]
        print_scan(results)
        captured = capsys.readouterr()
        assert "1 interface " in captured.out
        assert "1 method" in captured.out
        assert "interfaces" not in captured.out
        assert "methods" not in captured.out

    def test_plural_forms(self, capsys):
        iface_a = RpcInterface(uuid="AAAA", method_count=10)
        iface_b = RpcInterface(uuid="BBBB", method_count=20)
        results = [{"file": "multi.dll", "interfaces": [iface_a, iface_b]}]
        print_scan(results)
        captured = capsys.readouterr()
        assert "2 interfaces" in captured.out
        assert "30 methods" in captured.out

    def test_skips_empty(self, capsys):
        results = [{"file": "empty.dll", "interfaces": []}]
        print_scan(results)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_deduplicates_by_uuid(self, capsys):
        ndr20 = RpcInterface(uuid="AAAA-1111", method_count=5, syntax="ndr20")
        ndr64 = RpcInterface(uuid="AAAA-1111", method_count=5, syntax="ndr64")
        results = [{"file": "dual.dll", "interfaces": [ndr20, ndr64]}]
        print_scan(results)
        captured = capsys.readouterr()
        assert "1 interface " in captured.out
        assert "5 method" in captured.out

    def test_empty_results(self, capsys):
        print_scan([])
        captured = capsys.readouterr()
        assert captured.out == ""


class TestPrintSummary:
    def test_summary_output(self, capsys):
        iface = RpcInterface(uuid="TEST", method_count=5)
        results = [{"file": "test.dll", "interfaces": [iface]}]
        print_summary(results)
        captured = capsys.readouterr()
        assert "test.dll" in captured.out
        assert "5" in captured.out

    def test_summary_skips_empty(self, capsys):
        results = [{"file": "empty.dll", "interfaces": []}]
        print_summary(results)
        captured = capsys.readouterr()
        assert "empty.dll" not in captured.out


def run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["rpcpeek"] + argv)
    try:
        main()
        return 0
    except SystemExit as e:
        return e.code


class TestMainDirect:
    def test_json_output(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(fixture_dll), "--format", "json"])
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert len(data[0]["interfaces"]) == 6

    def test_table_output(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(fixture_dll)])
        assert code == 0
        captured = capsys.readouterr()
        assert "C503F532" in captured.out

    def test_csv_output(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(fixture_dll), "--format", "csv"])
        assert code == 0
        captured = capsys.readouterr()
        assert "file,uuid,name,syntax" in captured.out

    def test_summary_output(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(fixture_dll), "--summary"])
        assert code == 0
        captured = capsys.readouterr()
        assert "MpSvc" in captured.out

    def test_interface_filter(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(fixture_dll), "--interface", "C503F532", "--format", "json"])
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        for iface in data[0]["interfaces"]:
            assert "C503F532" in iface["uuid"]

    def test_json_flag_alias(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(fixture_dll), "--json"])
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data[0]["interfaces"]) == 6

    def test_diff_mode(self, fixture_dll, capsys, monkeypatch):
        p = str(fixture_dll)
        code = run_main(monkeypatch, ["--diff", p, p])
        assert code == 0
        captured = capsys.readouterr()
        assert "No differences found" in captured.out

    def test_diff_cross_file(self, fixture_dll, lsasrv_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, ["--diff", str(fixture_dll), str(lsasrv_dll)])
        assert code == 0
        captured = capsys.readouterr()
        assert "+" in captured.out or "-" in captured.out

    def test_no_args_exits_1(self, capsys, monkeypatch):
        code = run_main(monkeypatch, [])
        assert code == 1

    def test_file_not_found_exits_2(self, capsys, monkeypatch):
        code = run_main(monkeypatch, ["nonexistent_fakefile.dll"])
        assert code == 2

    def test_method_highlight(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(fixture_dll), "--method", "161"])
        assert code == 0
        captured = capsys.readouterr()
        assert "<--" in captured.out

    def test_dir_mode(self, capsys, monkeypatch):
        from tests.conftest import FIXTURE_DIR
        code = run_main(monkeypatch, ["--dir", str(FIXTURE_DIR), "--summary"])
        assert code == 0
        captured = capsys.readouterr()
        assert "MpSvc" in captured.out

    def test_dir_no_dlls_exits_2(self, tmp_path, capsys, monkeypatch):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        code = run_main(monkeypatch, ["--dir", str(empty_dir)])
        assert code == 2

    def test_scan_single_dll(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, ["--scan", str(fixture_dll)])
        assert code == 0
        captured = capsys.readouterr()
        assert "MpSvc" in captured.out
        assert "interface" in captured.out
        assert "method" in captured.out

    def test_scan_dir(self, capsys, monkeypatch):
        from tests.conftest import FIXTURE_DIR
        code = run_main(monkeypatch, ["--scan", str(FIXTURE_DIR)])
        assert code == 0
        captured = capsys.readouterr()
        assert "MpSvc" in captured.out
        assert "lsasrv" in captured.out

    def test_scan_no_rpc_dll(self, norpc_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, ["--scan", str(norpc_dll)])
        assert code == 1
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_scan_nonexistent_path(self, capsys, monkeypatch):
        code = run_main(monkeypatch, ["--scan", "/nonexistent/path"])
        assert code == 2

    def test_scan_empty_dir(self, tmp_path, capsys, monkeypatch):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        code = run_main(monkeypatch, ["--scan", str(empty_dir)])
        assert code == 2

    def test_scan_with_interface_filter(self, capsys, monkeypatch):
        from tests.conftest import FIXTURE_DIR
        code = run_main(monkeypatch, ["--scan", str(FIXTURE_DIR), "--interface", "12345778"])
        assert code == 0
        captured = capsys.readouterr()
        assert "lsasrv" in captured.out
        assert "MpSvc" not in captured.out

    def test_triage_output(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(fixture_dll), "--triage"])
        assert code == 0
        captured = capsys.readouterr()
        assert "auth" in captured.out
        assert "params" in captured.out
        assert "struct*" in captured.out

    def test_triage_with_interface(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(fixture_dll), "--triage", "--interface", "C503F532"])
        assert code == 0
        captured = capsys.readouterr()
        assert "C503F532" in captured.out
        assert captured.out.count("Interface:") == 1

    def test_triage_json(self, fixture_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(fixture_dll), "--triage", "--json"])
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        ndr20 = [i for i in data[0]["interfaces"] if i.get("syntax") == "ndr20"]
        m161 = ndr20[0]["methods"][161]
        assert "param_types" in m161
        assert "auth_check" in m161

    def test_triage_norpc(self, norpc_dll, capsys, monkeypatch):
        code = run_main(monkeypatch, [str(norpc_dll), "--triage"])
        assert code == 1
        captured = capsys.readouterr()
        assert "no RPC interfaces found" in captured.out

    def test_triage_dir_mode(self, capsys, monkeypatch):
        from tests.conftest import FIXTURE_DIR
        code = run_main(monkeypatch, ["--dir", str(FIXTURE_DIR), "--triage"])
        assert code == 0
        captured = capsys.readouterr()
        assert "MpSvc" in captured.out
        assert "lsasrv" in captured.out


class TestCLISubprocess:
    def test_help_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--help"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "RPC interfaces" in result.stdout

    def test_no_args_exits_nonzero(self):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek"],
            capture_output=True, text=True,
        )
        assert result.returncode != 0

    def test_file_not_found_exit_2(self):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "nonexistent.dll"],
            capture_output=True, text=True,
        )
        assert result.returncode == 2
