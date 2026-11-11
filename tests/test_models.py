from rpcpeek.models import Section, RpcMethod, RpcInterface, PEInfo


class TestSection:
    def test_contains_rva_inside(self):
        sec = Section("test", virtual_address=0x1000, virtual_size=0x500, raw_offset=0x400, raw_size=0x500)
        assert sec.contains_rva(0x1000)
        assert sec.contains_rva(0x1200)
        assert sec.contains_rva(0x14FF)

    def test_contains_rva_outside(self):
        sec = Section("test", virtual_address=0x1000, virtual_size=0x500, raw_offset=0x400, raw_size=0x500)
        assert not sec.contains_rva(0x0FFF)
        assert not sec.contains_rva(0x1500)
        assert not sec.contains_rva(0x0)

    def test_contains_rva_uses_max_of_virtual_and_raw_size(self):
        sec = Section("test", virtual_address=0x1000, virtual_size=0x100, raw_offset=0x400, raw_size=0x500)
        assert sec.contains_rva(0x1400)

    def test_rva_to_offset(self):
        sec = Section("test", virtual_address=0x1000, virtual_size=0x500, raw_offset=0x400, raw_size=0x500)
        assert sec.rva_to_offset(0x1000) == 0x400
        assert sec.rva_to_offset(0x1100) == 0x500


class TestRpcMethod:
    def test_handler_hex(self):
        m = RpcMethod(index=0, handler_rva=0x16c950)
        assert m.handler_hex == "0x16c950"

    def test_handler_hex_zero(self):
        m = RpcMethod(index=0, handler_rva=0)
        assert m.handler_hex == "0x0"

    def test_defaults(self):
        m = RpcMethod(index=5, handler_rva=0x1000)
        assert m.proc_num == -1
        assert m.stack_size == 0
        assert m.param_count == 0
        assert m.error == ""


class TestRpcInterface:
    def test_default_methods_list(self):
        iface = RpcInterface(uuid="TEST-UUID", method_count=0)
        assert iface.methods == []
        assert isinstance(iface.methods, list)

    def test_default_syntax(self):
        iface = RpcInterface(uuid="TEST-UUID", method_count=0)
        assert iface.syntax == "ndr20"

    def test_methods_not_shared(self):
        a = RpcInterface(uuid="A", method_count=0)
        b = RpcInterface(uuid="B", method_count=0)
        a.methods.append("x")
        assert b.methods == []


class TestPEInfo:
    def test_fields(self):
        info = PEInfo(filename="test.dll", image_base=0x180000000, sections=[], import_rva=0x1000)
        assert info.filename == "test.dll"
        assert info.image_base == 0x180000000

    def test_default_is_pe32plus(self):
        info = PEInfo(filename="test.dll", image_base=0, sections=[], import_rva=0)
        assert info.is_pe32plus is True
