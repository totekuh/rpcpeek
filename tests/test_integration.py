import csv
import io
import json
import subprocess
import sys

import pytest

from rpcpeek.cli import analyze_file


class TestMpSvcAnalysis:
    def test_result_structure(self, parsed_result):
        assert "file" in parsed_result
        assert "rpc_imports" in parsed_result
        assert "interfaces" in parsed_result

    def test_filename(self, parsed_result):
        assert parsed_result["file"] == "MpSvc_4.18.26060.3008.dll"

    def test_ndr20_interface_count(self, parsed_result):
        ndr20 = [i for i in parsed_result["interfaces"] if i.syntax == "ndr20"]
        assert len(ndr20) == 3

    def test_ndr64_interface_count(self, parsed_result):
        ndr64 = [i for i in parsed_result["interfaces"] if i.syntax == "ndr64"]
        assert len(ndr64) == 3

    def test_total_interface_count(self, parsed_result):
        assert len(parsed_result["interfaces"]) == 6

    def test_interface_uuids(self, parsed_result):
        uuids = set(i.uuid for i in parsed_result["interfaces"])
        assert "C503F532-443A-4C69-8300-CCD1FBDB3839" in uuids
        assert "474BDF75-2E82-4E21-B41A-F11CC16A839F" in uuids
        assert "0DD94748-2FF1-11EE-BE56-0242AC120002" in uuids

    def test_ndr20_method_counts(self, parsed_result):
        ndr20 = [i for i in parsed_result["interfaces"] if i.syntax == "ndr20"]
        counts = [i.method_count for i in ndr20]
        assert counts == [238, 2, 57]

    def test_total_ndr20_methods(self, parsed_result):
        ndr20 = [i for i in parsed_result["interfaces"] if i.syntax == "ndr20"]
        total = sum(i.method_count for i in ndr20)
        assert total == 297

    def test_rpc_imports_rpcrt4(self, parsed_result):
        assert "RPCRT4.dll" in parsed_result["rpc_imports"]
        funcs = parsed_result["rpc_imports"]["RPCRT4.dll"]
        assert len(funcs) == 15
        assert "RpcServerRegisterIfEx" in funcs

    def test_method_161(self, parsed_result):
        ndr20 = [i for i in parsed_result["interfaces"] if i.syntax == "ndr20"]
        iface = ndr20[0]
        m = iface.methods[161]
        assert m.index == 161
        assert m.handler_rva == 1493328
        assert m.proc_num == 161
        assert m.stack_size == 48
        assert m.param_count == 5
        assert m.client_buffer == 16
        assert m.server_buffer == 36

    def test_method_0_interface_0(self, parsed_result):
        ndr20 = [i for i in parsed_result["interfaces"] if i.syntax == "ndr20"]
        m = ndr20[0].methods[0]
        assert m.index == 0
        assert m.handler_rva == 3262112
        assert m.stack_size == 40
        assert m.param_count == 4

    def test_last_method_interface_2(self, parsed_result):
        ndr20 = [i for i in parsed_result["interfaces"] if i.syntax == "ndr20"]
        iface = ndr20[2]
        m = iface.methods[-1]
        assert m.index == 56
        assert m.handler_rva == 4633392
        assert m.param_count == 7

    def test_interface_1_methods(self, parsed_result):
        ndr20 = [i for i in parsed_result["interfaces"] if i.syntax == "ndr20"]
        iface = ndr20[1]
        assert iface.method_count == 2
        assert len(iface.methods) == 2
        assert iface.methods[0].handler_rva == 4815728
        assert iface.methods[0].param_count == 2
        assert iface.methods[1].param_count == 7

    def test_ndr64_handlers_match_ndr20(self, parsed_result):
        by_uuid = {}
        for i in parsed_result["interfaces"]:
            by_uuid.setdefault(i.uuid, {})[i.syntax] = i
        for uuid, syntaxes in by_uuid.items():
            if "ndr20" in syntaxes and "ndr64" in syntaxes:
                for j in range(len(syntaxes["ndr20"].methods)):
                    assert syntaxes["ndr20"].methods[j].handler_rva == syntaxes["ndr64"].methods[j].handler_rva


class TestMpSvcTriage:
    @pytest.fixture
    def triage_result(self, fixture_dll):
        return analyze_file(fixture_dll, triage=True)

    def test_method_161_param_types(self, triage_result):
        ndr20 = [i for i in triage_result["interfaces"] if i.syntax == "ndr20"]
        m = ndr20[0].methods[161]
        assert m.param_types == ["int", "struct*", "int", "out*"]

    def test_method_161_auth_yes(self, triage_result):
        ndr20 = [i for i in triage_result["interfaces"] if i.syntax == "ndr20"]
        assert ndr20[0].methods[161].auth_check == "yes"

    def test_all_methods_have_auth(self, triage_result):
        ndr20 = [i for i in triage_result["interfaces"] if i.syntax == "ndr20" and i.methods]
        for iface in ndr20:
            for m in iface.methods:
                assert m.auth_check in ("yes", "none"), f"method {m.index}: auth_check='{m.auth_check}'"

    def test_param_types_populated(self, triage_result):
        ndr20 = [i for i in triage_result["interfaces"] if i.syntax == "ndr20" and i.method_count == 238][0]
        with_types = sum(1 for m in ndr20.methods if m.param_types)
        assert with_types > 180

    def test_has_struct_params(self, triage_result):
        ndr20 = [i for i in triage_result["interfaces"] if i.syntax == "ndr20" and i.method_count == 238][0]
        has_struct = any("struct" in t for m in ndr20.methods for t in m.param_types)
        assert has_struct

    def test_has_wstr_params(self, triage_result):
        ndr20 = [i for i in triage_result["interfaces"] if i.syntax == "ndr20" and i.method_count == 238][0]
        has_wstr = any("wstr" in t for m in ndr20.methods for t in m.param_types)
        assert has_wstr

    def test_has_no_auth_methods(self, triage_result):
        ndr20 = [i for i in triage_result["interfaces"] if i.syntax == "ndr20" and i.method_count == 238][0]
        no_auth = sum(1 for m in ndr20.methods if m.auth_check == "none")
        assert no_auth > 50

    def test_non_triage_no_auth_check(self, parsed_result):
        ndr20 = [i for i in parsed_result["interfaces"] if i.syntax == "ndr20"]
        for m in ndr20[0].methods:
            assert m.auth_check == ""


class TestLsasrvAnalysis:
    def test_ndr20_interface_count(self, lsasrv_result):
        ndr20 = [i for i in lsasrv_result["interfaces"] if i.syntax == "ndr20"]
        assert len(ndr20) == 13

    def test_ndr64_interface_count(self, lsasrv_result):
        ndr64 = [i for i in lsasrv_result["interfaces"] if i.syntax == "ndr64"]
        assert len(ndr64) == 7

    def test_samr_interface_present(self, lsasrv_result):
        samr = [i for i in lsasrv_result["interfaces"] if "12345778" in i.uuid]
        assert len(samr) == 2
        syntaxes = sorted(i.syntax for i in samr)
        assert syntaxes == ["ndr20", "ndr64"]

    def test_samr_method_count(self, lsasrv_result):
        samr = [i for i in lsasrv_result["interfaces"] if "12345778" in i.uuid]
        for i in samr:
            assert i.method_count == 154

    def test_samr_ndr64_method_parsing(self, lsasrv_result):
        samr64 = [i for i in lsasrv_result["interfaces"]
                  if "12345778" in i.uuid and i.syntax == "ndr64"][0]
        assert len(samr64.methods) == 154
        m0 = samr64.methods[0]
        assert m0.param_count > 0
        assert m0.stack_size > 0

    def test_no_direct_rpcrt4_imports(self, lsasrv_result):
        assert len(lsasrv_result["rpc_imports"]) == 0

    def test_zero_method_interfaces_exist(self, lsasrv_result):
        ndr20 = [i for i in lsasrv_result["interfaces"] if i.syntax == "ndr20"]
        zero_method = [i for i in ndr20 if i.method_count == 0]
        assert len(zero_method) == 6

    def test_ndr64_handlers_match_ndr20(self, lsasrv_result):
        by_uuid = {}
        for i in lsasrv_result["interfaces"]:
            by_uuid.setdefault(i.uuid, {})[i.syntax] = i
        for uuid, syntaxes in by_uuid.items():
            if "ndr20" in syntaxes and "ndr64" in syntaxes:
                ndr20 = syntaxes["ndr20"]
                ndr64 = syntaxes["ndr64"]
                assert ndr20.method_count == ndr64.method_count
                for j in range(len(ndr20.methods)):
                    assert ndr20.methods[j].handler_rva == ndr64.methods[j].handler_rva


class TestMpSvcCLI:
    @pytest.fixture
    def dll_path(self, fixture_dll):
        return str(fixture_dll)

    def test_json_output(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--format", "json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["file"] == "MpSvc_4.18.26060.3008.dll"
        assert len(data[0]["interfaces"]) == 6

    def test_json_flag_alias(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data[0]["interfaces"]) == 6

    def test_json_contains_ndr64_syntax(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        ndr64 = [i for i in data[0]["interfaces"] if i.get("syntax") == "ndr64"]
        assert len(ndr64) == 3

    def test_json_method_161_values(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        ndr20 = [i for i in data[0]["interfaces"] if i.get("syntax") == "ndr20"]
        m161 = ndr20[0]["methods"][161]
        assert m161["handler_rva"] == 1493328
        assert m161["proc_num"] == 161
        assert m161["param_count"] == 5

    def test_table_output(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "C503F532-443A-4C69-8300-CCD1FBDB3839" in result.stdout
        assert "474BDF75-2E82-4E21-B41A-F11CC16A839F" in result.stdout
        assert "0DD94748-2FF1-11EE-BE56-0242AC120002" in result.stdout
        assert "handler RVA" in result.stdout
        assert "[ndr64]" in result.stdout

    def test_table_shows_all_interfaces(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path],
            capture_output=True, text=True,
        )
        assert result.stdout.count("Interface:") == 6

    def test_method_highlight(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--method", "161"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "<--" in result.stdout

    def test_method_highlight_appears_in_ndr64_too(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--method", "0"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert result.stdout.count("<--") == 6

    def test_json_serializable(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        reserialized = json.dumps(data)
        assert json.loads(reserialized) == data

    def test_csv_output(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--format", "csv"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        header = rows[0]
        assert header == ["file", "uuid", "name", "syntax", "index", "handler_rva", "proc_num", "stack_size", "param_count"]
        assert len(rows) > 1

    def test_csv_row_count(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--format", "csv"],
            capture_output=True, text=True,
        )
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        data_rows = rows[1:]
        total_methods = 238 + 2 + 57
        assert len(data_rows) == total_methods * 2

    def test_csv_has_both_syntaxes(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--format", "csv"],
            capture_output=True, text=True,
        )
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        syntaxes = set(r[3] for r in rows[1:])
        assert syntaxes == {"ndr20", "ndr64"}

    def test_interface_filter_json(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--interface", "C503F532", "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data[0]["interfaces"]) == 2
        for iface in data[0]["interfaces"]:
            assert "C503F532" in iface["uuid"]

    def test_interface_filter_table(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--interface", "C503F532"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "C503F532" in result.stdout
        assert "474BDF75" not in result.stdout
        assert "0DD94748" not in result.stdout

    def test_interface_filter_csv(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--interface", "C503F532", "--format", "csv"],
            capture_output=True, text=True,
        )
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        for row in rows[1:]:
            assert "C503F532" in row[1]

    def test_interface_filter_no_match(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--interface", "ZZZZZZZZ", "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        data = json.loads(result.stdout)
        assert data[0]["interfaces"] == []

    def test_summary_output(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--summary"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "MpSvc" in result.stdout


class TestLsasrvCLI:
    @pytest.fixture
    def dll_path(self, lsasrv_dll):
        return str(lsasrv_dll)

    def test_json_has_ndr64(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        ndr64 = [i for i in data[0]["interfaces"] if i.get("syntax") == "ndr64"]
        assert len(ndr64) == 7

    def test_json_has_20_total_interfaces(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        assert len(data[0]["interfaces"]) == 20

    def test_json_samr_154_methods(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--interface", "12345778", "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        for iface in data[0]["interfaces"]:
            assert iface["method_count"] == 154

    def test_table_output(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "12345778-1234-ABCD-EF00-0123456789AB" in result.stdout

    def test_table_shows_ndr64_tag(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "[ndr64]" in result.stdout

    def test_table_shows_zero_method_interfaces(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path],
            capture_output=True, text=True,
        )
        assert "Methods:   0" in result.stdout

    def test_interface_filter_samr_json(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--interface", "12345778", "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data[0]["interfaces"]) == 2
        syntaxes = sorted(i["syntax"] for i in data[0]["interfaces"])
        assert syntaxes == ["ndr20", "ndr64"]

    def test_interface_filter_samr_table(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--interface", "12345778"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "12345778" in result.stdout
        assert result.stdout.count("Interface:") == 2

    def test_interface_filter_samr_csv(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--interface", "12345778", "--format", "csv"],
            capture_output=True, text=True,
        )
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        assert len(rows) == 1 + (154 * 2)
        for row in rows[1:]:
            assert "12345778" in row[1]

    def test_csv_output(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--format", "csv"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        syntaxes = set(r[3] for r in rows[1:])
        assert "ndr64" in syntaxes
        assert "ndr20" in syntaxes

    def test_method_highlight(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--method", "0"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "<--" in result.stdout

    def test_summary_output(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--summary"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "lsasrv" in result.stdout


class TestMpSvcTriageCLI:
    @pytest.fixture
    def dll_path(self, fixture_dll):
        return str(fixture_dll)

    def test_triage_output_format(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--triage"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "auth" in result.stdout
        assert "params" in result.stdout
        assert "Interface:" in result.stdout

    def test_triage_shows_param_types(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--triage"],
            capture_output=True, text=True,
        )
        assert "struct*" in result.stdout
        assert "int" in result.stdout
        assert "out*" in result.stdout

    def test_triage_shows_auth(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--triage"],
            capture_output=True, text=True,
        )
        assert "yes" in result.stdout
        assert "none" in result.stdout

    def test_triage_method_161(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--triage"],
            capture_output=True, text=True,
        )
        lines = result.stdout.split("\n")
        m161 = [l for l in lines if l.strip().startswith("161")]
        assert len(m161) == 1
        assert "struct*" in m161[0]
        assert "yes" in m161[0]

    def test_triage_skips_ndr64(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--triage"],
            capture_output=True, text=True,
        )
        assert "[ndr64]" not in result.stdout

    def test_triage_sorts_interesting_first(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--triage"],
            capture_output=True, text=True,
        )
        lines = result.stdout.split("\n")
        data_lines = [l for l in lines if l.strip() and l.strip()[0].isdigit()]
        if len(data_lines) >= 2:
            assert "none" in data_lines[0] or "struct" in data_lines[0] or "wstr" in data_lines[0]

    def test_triage_with_interface_filter(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--triage", "--interface", "C503F532"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "C503F532" in result.stdout
        assert result.stdout.count("Interface:") == 1

    def test_triage_json_includes_auth(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--triage", "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        ndr20 = [i for i in data[0]["interfaces"] if i.get("syntax") == "ndr20"]
        m161 = ndr20[0]["methods"][161]
        assert m161["param_types"] == ["int", "struct*", "int", "out*"]
        assert m161["auth_check"] == "yes"

    def test_triage_norpc_dll(self, norpc_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", str(norpc_dll), "--triage"],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "no RPC interfaces found" in result.stdout


class TestLsasrvTriageCLI:
    def test_triage_output(self, lsasrv_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", str(lsasrv_dll), "--triage"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "LSARPC" in result.stdout
        assert "struct" in result.stdout


class TestDirModeCLI:
    @pytest.fixture
    def fixtures_dir(self):
        from tests.conftest import FIXTURE_DIR
        return str(FIXTURE_DIR)

    def test_dir_summary(self, fixtures_dir):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--dir", fixtures_dir, "--summary"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "MpSvc" in result.stdout
        assert "lsasrv" in result.stdout

    def test_dir_json(self, fixtures_dir):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--dir", fixtures_dir, "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data) == 3
        filenames = sorted(d["file"] for d in data)
        assert "MpSvc_4.18.26060.3008.dll" in filenames
        assert "lsasrv.dll" in filenames
        assert "empty_norpc.dll" in filenames

    def test_dir_csv(self, fixtures_dir):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--dir", fixtures_dir, "--format", "csv"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        files = set(r[0] for r in rows[1:])
        assert "MpSvc_4.18.26060.3008.dll" in files
        assert "lsasrv.dll" in files

    def test_dir_table(self, fixtures_dir):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--dir", fixtures_dir],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "C503F532" in result.stdout
        assert "12345778" in result.stdout

    def test_dir_with_interface_filter(self, fixtures_dir):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--dir", fixtures_dir, "--interface", "12345778", "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        for entry in data:
            for iface in entry["interfaces"]:
                assert "12345778" in iface["uuid"]


class TestScanCLI:
    @pytest.fixture
    def fixtures_dir(self):
        from tests.conftest import FIXTURE_DIR
        return str(FIXTURE_DIR)

    def test_scan_dir(self, fixtures_dir):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--scan", fixtures_dir],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "MpSvc" in result.stdout
        assert "lsasrv" in result.stdout
        assert "empty_norpc" not in result.stdout

    def test_scan_single_dll(self, fixture_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--scan", str(fixture_dll)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "MpSvc" in result.stdout
        assert "interface" in result.stdout

    def test_scan_norpc_exit_1(self, norpc_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--scan", str(norpc_dll)],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert result.stdout.strip() == ""

    def test_scan_with_interface_filter(self, fixtures_dir):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--scan", fixtures_dir, "--interface", "12345778"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "lsasrv" in result.stdout
        assert "MpSvc" not in result.stdout

    def test_scan_dedup_counts(self, fixture_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--scan", str(fixture_dll)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        line = result.stdout.strip()
        assert "3 interfaces" in line
        assert "297 methods" in line


class TestDiffCLI:
    def test_diff_same_file(self, fixture_dll):
        p = str(fixture_dll)
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--diff", p, p],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "No differences found" in result.stdout

    def test_diff_same_file_lsasrv(self, lsasrv_dll):
        p = str(lsasrv_dll)
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--diff", p, p],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "No differences found" in result.stdout

    def test_diff_different_files(self, fixture_dll, lsasrv_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--diff", str(fixture_dll), str(lsasrv_dll)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "+" in result.stdout
        assert "-" in result.stdout

    def test_diff_shows_unique_interfaces(self, fixture_dll, lsasrv_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--diff", str(fixture_dll), str(lsasrv_dll)],
            capture_output=True, text=True,
        )
        assert "C503F532" in result.stdout
        assert "12345778" in result.stdout

    def test_diff_reversed(self, fixture_dll, lsasrv_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--diff", str(lsasrv_dll), str(fixture_dll)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "+" in result.stdout
        assert "-" in result.stdout

    def test_diff_shows_known_names(self, fixture_dll, lsasrv_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--diff", str(fixture_dll), str(lsasrv_dll)],
            capture_output=True, text=True,
        )
        assert "LSARPC" in result.stdout


class TestNameResolution:
    def test_lsasrv_table_shows_lsarpc(self, lsasrv_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", str(lsasrv_dll)],
            capture_output=True, text=True,
        )
        assert "LSARPC 12345778-1234-ABCD-EF00-0123456789AB" in result.stdout

    def test_lsasrv_table_shows_lsa_dssetup(self, lsasrv_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", str(lsasrv_dll)],
            capture_output=True, text=True,
        )
        assert "LSA-DSSETUP" in result.stdout

    def test_lsasrv_json_has_name_field(self, lsasrv_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", str(lsasrv_dll), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        named = [i for i in data[0]["interfaces"] if "name" in i]
        assert len(named) > 0
        names = [i["name"] for i in named]
        assert "LSARPC" in names

    def test_lsasrv_csv_name_column(self, lsasrv_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", str(lsasrv_dll), "--format", "csv"],
            capture_output=True, text=True,
        )
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        assert rows[0][2] == "name"
        name_values = set(r[2] for r in rows[1:] if r[2])
        assert "LSARPC" in name_values

    def test_mpsvc_no_known_names(self, fixture_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", str(fixture_dll), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        named = [i for i in data[0]["interfaces"] if "name" in i]
        assert len(named) == 0

    def test_mpsvc_csv_empty_names(self, fixture_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", str(fixture_dll), "--format", "csv"],
            capture_output=True, text=True,
        )
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        name_values = set(r[2] for r in rows[1:])
        assert name_values == {""}


class TestNoRpcDllAnalysis:
    def test_no_interfaces(self, norpc_result):
        assert len(norpc_result["interfaces"]) == 0

    def test_no_rpc_imports(self, norpc_result):
        assert len(norpc_result["rpc_imports"]) == 0

    def test_filename(self, norpc_result):
        assert norpc_result["file"] == "empty_norpc.dll"

    def test_result_structure(self, norpc_result):
        assert "file" in norpc_result
        assert "rpc_imports" in norpc_result
        assert "interfaces" in norpc_result

    def test_pe_parses_correctly(self, norpc_bytes):
        from rpcpeek.pe import PEParser
        parser = PEParser(norpc_bytes)
        info = parser.parse()
        assert info.is_pe32plus is True
        assert info.image_base == 0x180000000
        assert len(info.sections) == 4
        names = [s.name for s in info.sections]
        assert ".text" in names
        assert ".rdata" in names
        assert ".edata" in names
        assert ".idata" in names

    def test_has_non_rpc_imports(self, norpc_bytes):
        from rpcpeek.pe import PEParser
        from rpcpeek.ndr import RpcExtractor
        parser = PEParser(norpc_bytes)
        info = parser.parse()
        ext = RpcExtractor(norpc_bytes, info, parser)
        imports = ext.extract_imports()
        assert "KERNEL32.dll" in imports
        funcs = imports["KERNEL32.dll"]
        assert "GetProcessHeap" in funcs
        assert "HeapAlloc" in funcs
        assert "HeapFree" in funcs


class TestNoRpcDllCLI:
    @pytest.fixture
    def dll_path(self, norpc_dll):
        return str(norpc_dll)

    def test_table_no_interfaces(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "no RPC interfaces found" in result.stdout

    def test_json_empty_interfaces(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        data = json.loads(result.stdout)
        assert len(data) == 1
        assert data[0]["interfaces"] == []
        assert data[0]["rpc_imports"] == {}

    def test_csv_header_only(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--format", "csv"],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0][0] == "file"

    def test_summary_skips_empty(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path, "--summary"],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "empty_norpc" not in result.stdout

    def test_exit_code_1_no_interfaces(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", dll_path],
            capture_output=True, text=True,
        )
        assert result.returncode == 1

    def test_diff_norpc_vs_mpsvc(self, dll_path, fixture_dll):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--diff", dll_path, str(fixture_dll)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "+" in result.stdout
        assert "C503F532" in result.stdout

    def test_diff_norpc_vs_norpc(self, dll_path):
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--diff", dll_path, dll_path],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "No differences found" in result.stdout

    def test_dir_with_norpc(self):
        from tests.conftest import FIXTURE_DIR
        result = subprocess.run(
            [sys.executable, "-m", "rpcpeek", "--dir", str(FIXTURE_DIR), "--summary"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "empty_norpc" not in result.stdout
        assert "MpSvc" in result.stdout
