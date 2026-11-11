import struct
import sys

from rpcpeek.models import RpcMethod, RpcInterface, PEInfo
from rpcpeek.pe import PEParser


NDR20_TRANSFER_SYNTAX = bytes([
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
])

NDR64_TRANSFER_SYNTAX = bytes([
    0x33, 0x05, 0x71, 0x71, 0xBA, 0xBE, 0x37, 0x49,
    0x83, 0x19, 0xB5, 0xDB, 0xEF, 0x9C, 0xCC, 0x36,
])


_FC_BASETYPE = frozenset(range(0x01, 0x11)) | {0xB8, 0xB9}
_FC_POINTER = frozenset({0x11, 0x12, 0x13, 0x14})
_FC_STRUCT = frozenset({0x15, 0x16, 0x17, 0x18, 0x19, 0x1A})
_FC_ARRAY = frozenset({0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20})
_FC_STRING = frozenset({0x22, 0x23, 0x24})
_FC_WSTRING = frozenset({0x25})
_FC_CONTEXT = frozenset({0x2C})


def _classify_fc(fc):
    if fc in _FC_BASETYPE:
        return "int"
    if fc in _FC_STRING:
        return "str"
    if fc in _FC_WSTRING:
        return "wstr"
    if fc in _FC_STRUCT:
        return "struct"
    if fc in _FC_ARRAY:
        return "array"
    if fc in _FC_CONTEXT:
        return "ctx"
    return "ptr"


class RpcExtractor:
    def __init__(self, data: bytes, pe_info: PEInfo, parser: PEParser):
        self.data = data
        self.pe = pe_info
        self.parser = parser

    def _r2o(self, rva: int):
        return self.parser.rva_to_offset(self.pe.sections, rva)

    def extract_imports(self) -> dict:
        if not self.pe.is_pe32plus:
            print(f"Warning: {self.pe.filename} is 32-bit PE, skipping (x64 only)", file=sys.stderr)
            return {}

        result = {}
        offset = self._r2o(self.pe.import_rva)
        if offset is None:
            return result

        idx = 0
        while True:
            entry = self.data[offset + idx * 20:offset + idx * 20 + 20]
            if len(entry) < 20 or entry == b"\0" * 20:
                break

            oft, _, _, name_rva, first_thunk = struct.unpack("<IIIII", entry)
            dll_name = self.parser.read_cstring(self._r2o(name_rva))
            thunk_offset = self._r2o(oft or first_thunk)
            functions = []

            if thunk_offset:
                j = 0
                while True:
                    val = struct.unpack_from("<Q", self.data, thunk_offset + j * 8)[0]
                    if val == 0:
                        break
                    if not (val >> 63):
                        name_offset = self._r2o(val)
                        if name_offset:
                            functions.append(self.parser.read_cstring(name_offset + 2))
                    j += 1

            result[dll_name] = functions
            idx += 1

        return result

    def _get_type_format_base(self, stub_desc_ptr):
        sd_off = self._r2o(stub_desc_ptr - self.pe.image_base)
        if sd_off is None:
            return None
        try:
            type_fmt_ptr = struct.unpack_from("<Q", self.data, sd_off + 0x40)[0]
            return self._r2o(type_fmt_ptr - self.pe.image_base)
        except (struct.error, IndexError):
            return None

    def _follow_pointer(self, type_base, offset):
        ptr_attrs = self.data[type_base + offset + 1]
        if ptr_attrs & 0x02:
            return _classify_fc(self.data[type_base + offset + 2])
        rel = struct.unpack_from("<h", self.data, type_base + offset + 2)[0]
        return _classify_fc(self.data[type_base + offset + 2 + rel])

    def _parse_param_descs(self, start, count, type_fmt_base):
        types = []
        for i in range(count):
            off = start + i * 6
            attrs = struct.unpack_from("<H", self.data, off)[0]
            type_info = struct.unpack_from("<H", self.data, off + 4)[0]

            if attrs & 0x0020:
                continue
            if (attrs & 0x0010) and not (attrs & 0x0008):
                types.append("out*")
                continue
            if attrs & 0x0040:
                types.append("int")
                continue

            is_simple_ref = bool(attrs & 0x0100)
            try:
                fc = self.data[type_fmt_base + type_info]
                if is_simple_ref:
                    types.append(_classify_fc(fc) + "*")
                elif fc in _FC_POINTER:
                    types.append(self._follow_pointer(type_fmt_base, type_info) + "*")
                else:
                    types.append(_classify_fc(fc))
            except (IndexError, struct.error):
                types.append("ptr")

        return types

    def _parse_ndr20_methods(self, io: int, do: int, method_count: int) -> list:
        stub_desc_ptr, srv_dispatch, proc_string, fmt_offset = struct.unpack_from("<QQQQ", self.data, io)
        do_off = self._r2o(srv_dispatch - self.pe.image_base)
        fo = self._r2o(fmt_offset - self.pe.image_base)
        po = self._r2o(proc_string - self.pe.image_base)
        type_fmt_base = self._get_type_format_base(stub_desc_ptr)

        methods = []
        if not (do_off and fo and po):
            return methods

        for k in range(method_count):
            fn_ptr = struct.unpack_from("<Q", self.data, do + k * 8)[0]
            fmt_off = struct.unpack_from("<H", self.data, fo + k * 2)[0]

            method = RpcMethod(index=k, handler_rva=fn_ptr - self.pe.image_base)
            try:
                header = self.data[po + fmt_off:po + fmt_off + 24]
                handle_type = header[0]
                method.proc_num = struct.unpack_from("<H", header, 6)[0]
                method.stack_size = struct.unpack_from("<H", header, 8)[0]

                q = 10
                if handle_type == 0:
                    ht = header[q]
                    q += 6 if ht == 0x31 else 4

                method.client_buffer = struct.unpack_from("<H", header, q)[0]
                method.server_buffer = struct.unpack_from("<H", header, q + 2)[0]
                oi2_flags = header[q + 4]
                q += 5
                method.param_count = header[q]

                pd_start = po + fmt_off + q + 1
                if oi2_flags & 0x40:
                    pd_start += self.data[pd_start]
                if type_fmt_base is not None and method.param_count > 0:
                    method.param_types = self._parse_param_descs(
                        pd_start, method.param_count, type_fmt_base
                    )
            except Exception as ex:
                method.error = str(ex)

            methods.append(method)

        return methods

    def scan_auth_checks(self, interfaces):
        marker = struct.pack("<I", 0x80070005)
        for iface in interfaces:
            if not iface.methods:
                continue
            sorted_m = sorted(iface.methods, key=lambda m: m.handler_rva)
            for i, method in enumerate(sorted_m):
                start = self._r2o(method.handler_rva)
                if start is None:
                    method.auth_check = "?"
                    continue
                if i + 1 < len(sorted_m):
                    end = self._r2o(sorted_m[i + 1].handler_rva)
                    if end is None or end <= start:
                        end = min(start + 0x2000, len(self.data))
                else:
                    end = min(start + 0x2000, len(self.data))
                method.auth_check = "yes" if marker in self.data[start:end] else "none"

    def _parse_ndr64_methods(self, io: int, do: int, method_count: int) -> list:
        n_count = struct.unpack_from("<Q", self.data, io + 0x30)[0]
        if n_count < 2:
            return []

        syntax_info_ptr = struct.unpack_from("<Q", self.data, io + 0x38)[0]
        si_off = self._r2o(syntax_info_ptr - self.pe.image_base)
        if si_off is None:
            return []

        ndr64_entry = si_off + 0x50
        guid = self.data[ndr64_entry:ndr64_entry + 16]
        if guid != NDR64_TRANSFER_SYNTAX:
            return []

        fmt_offset_ptr = struct.unpack_from("<Q", self.data, ndr64_entry + 0x28)[0]
        fo = self._r2o(fmt_offset_ptr - self.pe.image_base)
        if fo is None:
            return []

        methods = []
        for k in range(method_count):
            fn_ptr = struct.unpack_from("<Q", self.data, do + k * 8)[0]
            proc_va = struct.unpack_from("<Q", self.data, fo + k * 8)[0]

            method = RpcMethod(index=k, handler_rva=fn_ptr - self.pe.image_base)
            try:
                po = self._r2o(proc_va - self.pe.image_base)
                if po is None:
                    method.error = "bad proc VA"
                    methods.append(method)
                    continue

                header = self.data[po:po + 0x18]
                method.proc_num = k
                method.stack_size = struct.unpack_from("<I", header, 0x04)[0]
                method.client_buffer = struct.unpack_from("<I", header, 0x0C)[0]
                method.server_buffer = struct.unpack_from("<I", header, 0x10)[0]
                method.param_count = struct.unpack_from("<H", header, 0x14)[0]
            except Exception as ex:
                method.error = str(ex)

            methods.append(method)

        return methods

    def extract_interfaces(self) -> list:
        if not self.pe.is_pe32plus:
            print(f"Warning: {self.pe.filename} is 32-bit PE, skipping (x64 only)", file=sys.stderr)
            return []

        interfaces = []
        search_pos = 0

        while True:
            found = self.data.find(NDR20_TRANSFER_SYNTAX, search_pos)
            if found == -1:
                break
            search_pos = found + 1

            base = found - 0x18
            if base < 0:
                continue
            if struct.unpack_from("<I", self.data, base)[0] != 0x60:
                continue

            d1, d2, d3 = struct.unpack_from("<IHH", self.data, base + 4)
            rest = self.data[base + 12:base + 20]
            uuid = f"{d1:08X}-{d2:04X}-{d3:04X}-{rest[:2].hex().upper()}-{rest[2:].hex().upper()}"

            dispatch_ptr = struct.unpack_from("<Q", self.data, base + 0x30)[0]
            interp_ptr = struct.unpack_from("<Q", self.data, base + 0x50)[0]

            method_count = 0
            dispatch_off = None
            if dispatch_ptr:
                dispatch_off = self._r2o(dispatch_ptr - self.pe.image_base)
                if dispatch_off:
                    method_count = struct.unpack_from("<I", self.data, dispatch_off)[0]

            iface = RpcInterface(uuid=uuid, method_count=method_count, syntax="ndr20")

            if interp_ptr and method_count:
                io = self._r2o(interp_ptr - self.pe.image_base)
                if io:
                    do = self._r2o(
                        struct.unpack_from("<Q", self.data, io + 0x08)[0] - self.pe.image_base
                    )
                    if do:
                        iface.methods = self._parse_ndr20_methods(io, do, method_count)

                        ndr64_methods = self._parse_ndr64_methods(io, do, method_count)
                        if ndr64_methods:
                            ndr64_iface = RpcInterface(
                                uuid=uuid,
                                method_count=method_count,
                                syntax="ndr64",
                                methods=ndr64_methods,
                            )
                            interfaces.append(iface)
                            interfaces.append(ndr64_iface)
                            continue

            interfaces.append(iface)

        return interfaces
