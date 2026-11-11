import struct

from rpcpeek.models import Section, PEInfo


class PEParser:
    def __init__(self, data: bytes):
        self.data = data

    def parse(self) -> PEInfo:
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        coff = e_lfanew + 4
        num_sections = struct.unpack_from("<H", self.data, coff + 2)[0]
        opt_header_size = struct.unpack_from("<H", self.data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", self.data, opt)[0]
        is_pe32plus = magic == 0x20B

        if is_pe32plus:
            image_base = struct.unpack_from("<Q", self.data, opt + 24)[0]
        else:
            image_base = struct.unpack_from("<I", self.data, opt + 28)[0]

        ddir_offset = opt + (112 if is_pe32plus else 96)
        import_rva = struct.unpack_from("<I", self.data, ddir_offset + 8)[0]

        sections = []
        sec_offset = opt + opt_header_size
        for i in range(num_sections):
            base = sec_offset + i * 40
            name = self.data[base:base + 8].rstrip(b"\0").decode(errors="replace")
            vsz, va, rsz, ptr = struct.unpack_from("<IIII", self.data, base + 8)
            sections.append(Section(name, va, vsz, ptr, rsz))

        return PEInfo("", image_base, sections, import_rva, is_pe32plus)

    def rva_to_offset(self, sections: list, rva: int):
        for sec in sections:
            if sec.contains_rva(rva):
                return sec.rva_to_offset(rva)
        return None

    def read_cstring(self, offset: int, max_length: int = 200) -> str:
        if offset is None:
            return ""
        end = self.data.find(b"\0", offset)
        if end == -1:
            end = offset + max_length
        return self.data[offset:end].decode("ascii", errors="replace")[:max_length]
