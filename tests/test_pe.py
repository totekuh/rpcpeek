import pytest

from rpcpeek.pe import PEParser


class TestPEParser:
    def test_parse_header(self, dll_bytes):
        parser = PEParser(dll_bytes)
        info = parser.parse()
        assert info.image_base > 0
        assert len(info.sections) > 0
        assert info.import_rva > 0

    def test_is_pe32plus(self, dll_bytes):
        parser = PEParser(dll_bytes)
        info = parser.parse()
        assert info.is_pe32plus is True

    def test_is_pe32plus_lsasrv(self, lsasrv_bytes):
        parser = PEParser(lsasrv_bytes)
        info = parser.parse()
        assert info.is_pe32plus is True

    def test_section_names(self, dll_bytes):
        parser = PEParser(dll_bytes)
        info = parser.parse()
        names = [s.name for s in info.sections]
        assert ".text" in names
        assert ".rdata" in names

    def test_rva_to_offset_valid(self, dll_bytes):
        parser = PEParser(dll_bytes)
        info = parser.parse()
        text_sec = next(s for s in info.sections if s.name == ".text")
        offset = parser.rva_to_offset(info.sections, text_sec.virtual_address)
        assert offset == text_sec.raw_offset

    def test_rva_to_offset_invalid(self, dll_bytes):
        parser = PEParser(dll_bytes)
        info = parser.parse()
        assert parser.rva_to_offset(info.sections, 0xFFFFFFFF) is None

    def test_read_cstring(self, dll_bytes):
        parser = PEParser(dll_bytes)
        result = parser.read_cstring(None)
        assert result == ""

    def test_read_cstring_max_length(self, dll_bytes):
        parser = PEParser(dll_bytes)
        result = parser.read_cstring(0, max_length=10)
        assert len(result) <= 10
