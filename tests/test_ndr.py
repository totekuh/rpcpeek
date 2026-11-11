import pytest

from rpcpeek.pe import PEParser
from rpcpeek.ndr import RpcExtractor, NDR20_TRANSFER_SYNTAX, NDR64_TRANSFER_SYNTAX


class TestNDR20TransferSyntax:
    def test_length(self):
        assert len(NDR20_TRANSFER_SYNTAX) == 16

    def test_known_bytes(self):
        assert NDR20_TRANSFER_SYNTAX[0] == 0x04
        assert NDR20_TRANSFER_SYNTAX[1] == 0x5D


class TestNDR64TransferSyntax:
    def test_length(self):
        assert len(NDR64_TRANSFER_SYNTAX) == 16

    def test_known_bytes(self):
        assert NDR64_TRANSFER_SYNTAX[0] == 0x33
        assert NDR64_TRANSFER_SYNTAX[1] == 0x05

    def test_different_from_ndr20(self):
        assert NDR64_TRANSFER_SYNTAX != NDR20_TRANSFER_SYNTAX


@pytest.fixture(scope="module")
def extractor(dll_bytes):
    parser = PEParser(dll_bytes)
    pe_info = parser.parse()
    return RpcExtractor(dll_bytes, pe_info, parser)


@pytest.fixture(scope="module")
def lsasrv_extractor(lsasrv_bytes):
    parser = PEParser(lsasrv_bytes)
    pe_info = parser.parse()
    return RpcExtractor(lsasrv_bytes, pe_info, parser)


class TestParamTypeClassification:
    def test_mpsvc_method_161_param_types(self, extractor):
        interfaces = extractor.extract_interfaces()
        ndr20 = [i for i in interfaces if i.syntax == "ndr20" and i.method_count == 238][0]
        m = ndr20.methods[161]
        assert m.param_types == ["int", "struct*", "int", "out*"]

    def test_mpsvc_method_0_has_param_types(self, extractor):
        interfaces = extractor.extract_interfaces()
        ndr20 = [i for i in interfaces if i.syntax == "ndr20" and i.method_count == 238][0]
        m = ndr20.methods[0]
        assert len(m.param_types) > 0

    def test_param_types_only_known_categories(self, extractor):
        interfaces = extractor.extract_interfaces()
        ndr20 = [i for i in interfaces if i.syntax == "ndr20" and i.method_count == 238][0]
        known = {"int", "str", "wstr", "struct", "array", "ctx", "ptr", "out"}
        for m in ndr20.methods:
            for t in m.param_types:
                base = t.rstrip("*")
                assert base in known, f"method {m.index}: unknown type '{t}'"

    def test_methods_with_params_have_types(self, extractor):
        interfaces = extractor.extract_interfaces()
        ndr20 = [i for i in interfaces if i.syntax == "ndr20" and i.method_count == 238][0]
        has_types = sum(1 for m in ndr20.methods if m.param_types)
        assert has_types > 180

    def test_ndr64_methods_no_param_types(self, extractor):
        interfaces = extractor.extract_interfaces()
        ndr64 = [i for i in interfaces if i.syntax == "ndr64"]
        for iface in ndr64:
            for m in iface.methods:
                assert m.param_types == []

    def test_lsasrv_samr_has_param_types(self, lsasrv_extractor):
        interfaces = lsasrv_extractor.extract_interfaces()
        samr = [i for i in interfaces if "12345778" in i.uuid and i.syntax == "ndr20"][0]
        has_types = sum(1 for m in samr.methods if m.param_types)
        assert has_types > 60

    def test_lsasrv_samr_method_5_has_structs(self, lsasrv_extractor):
        interfaces = lsasrv_extractor.extract_interfaces()
        samr = [i for i in interfaces if "12345778" in i.uuid and i.syntax == "ndr20"][0]
        m5 = samr.methods[5]
        struct_params = [t for t in m5.param_types if "struct" in t]
        assert len(struct_params) > 0


class TestAuthHeuristic:
    def test_scan_fills_auth_check(self, extractor):
        interfaces = extractor.extract_interfaces()
        ndr20 = [i for i in interfaces if i.syntax == "ndr20" and i.method_count == 238][0]
        extractor.scan_auth_checks(interfaces)
        filled = sum(1 for m in ndr20.methods if m.auth_check in ("yes", "none"))
        assert filled == len(ndr20.methods)

    def test_method_161_auth_yes(self, extractor):
        interfaces = extractor.extract_interfaces()
        ndr20 = [i for i in interfaces if i.syntax == "ndr20" and i.method_count == 238][0]
        extractor.scan_auth_checks(interfaces)
        assert ndr20.methods[161].auth_check == "yes"

    def test_has_both_yes_and_none(self, extractor):
        interfaces = extractor.extract_interfaces()
        ndr20 = [i for i in interfaces if i.syntax == "ndr20" and i.method_count == 238][0]
        extractor.scan_auth_checks(interfaces)
        values = set(m.auth_check for m in ndr20.methods)
        assert "yes" in values
        assert "none" in values

    def test_without_scan_auth_empty(self):
        from rpcpeek.models import RpcMethod
        m = RpcMethod(index=0, handler_rva=0x1000)
        assert m.auth_check == ""

    def test_lsasrv_auth_scan(self, lsasrv_extractor):
        interfaces = lsasrv_extractor.extract_interfaces()
        lsasrv_extractor.scan_auth_checks(interfaces)
        ndr20 = [i for i in interfaces if i.syntax == "ndr20" and i.methods]
        filled = 0
        for iface in ndr20:
            for m in iface.methods:
                if m.auth_check in ("yes", "none"):
                    filled += 1
        assert filled > 0


class TestRpcExtractor:
    def test_extract_imports_has_rpcrt4(self, extractor):
        imports = extractor.extract_imports()
        assert "RPCRT4.dll" in imports

    def test_extract_imports_function_count(self, extractor):
        imports = extractor.extract_imports()
        all_funcs = []
        for funcs in imports.values():
            all_funcs.extend(funcs)
        assert len(all_funcs) > 0

    def test_extract_interfaces_returns_list(self, extractor):
        interfaces = extractor.extract_interfaces()
        assert isinstance(interfaces, list)
        assert len(interfaces) > 0

    def test_extract_interfaces_have_uuids(self, extractor):
        interfaces = extractor.extract_interfaces()
        for iface in interfaces:
            assert iface.uuid
            assert "-" in iface.uuid

    def test_extract_interfaces_have_syntax(self, extractor):
        interfaces = extractor.extract_interfaces()
        for iface in interfaces:
            assert iface.syntax in ("ndr20", "ndr64")


class TestNDR64Extraction:
    def test_lsasrv_has_ndr64_interfaces(self, lsasrv_extractor):
        interfaces = lsasrv_extractor.extract_interfaces()
        ndr64 = [i for i in interfaces if i.syntax == "ndr64"]
        assert len(ndr64) == 7

    def test_lsasrv_ndr20_count(self, lsasrv_extractor):
        interfaces = lsasrv_extractor.extract_interfaces()
        ndr20 = [i for i in interfaces if i.syntax == "ndr20"]
        assert len(ndr20) == 13

    def test_dual_registration_shared_handlers(self, lsasrv_extractor):
        interfaces = lsasrv_extractor.extract_interfaces()
        by_uuid = {}
        for i in interfaces:
            by_uuid.setdefault(i.uuid, {})[i.syntax] = i

        for uuid, syntaxes in by_uuid.items():
            if "ndr20" in syntaxes and "ndr64" in syntaxes:
                ndr20 = syntaxes["ndr20"]
                ndr64 = syntaxes["ndr64"]
                assert ndr20.method_count == ndr64.method_count
                for j in range(min(len(ndr20.methods), len(ndr64.methods))):
                    assert ndr20.methods[j].handler_rva == ndr64.methods[j].handler_rva

    def test_samr_ndr64_method_parsing(self, lsasrv_extractor):
        interfaces = lsasrv_extractor.extract_interfaces()
        samr64 = [i for i in interfaces if "12345778" in i.uuid and i.syntax == "ndr64"][0]
        assert samr64.method_count == 154
        assert len(samr64.methods) == 154
        m0 = samr64.methods[0]
        assert m0.param_count > 0
        assert m0.stack_size > 0
        assert m0.handler_rva > 0

    def test_mpsvc_ndr64_interfaces(self, extractor):
        interfaces = extractor.extract_interfaces()
        ndr64 = [i for i in interfaces if i.syntax == "ndr64"]
        assert len(ndr64) == 3
        ndr64_uuids = sorted(i.uuid for i in ndr64)
        ndr20 = [i for i in interfaces if i.syntax == "ndr20"]
        ndr20_with_methods = sorted(i.uuid for i in ndr20 if i.method_count > 0)
        assert ndr64_uuids == ndr20_with_methods
