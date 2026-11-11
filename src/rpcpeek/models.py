from dataclasses import dataclass, field


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + max(self.virtual_size, self.raw_size)

    def rva_to_offset(self, rva: int) -> int:
        return self.raw_offset + (rva - self.virtual_address)


@dataclass
class RpcMethod:
    index: int
    handler_rva: int
    proc_num: int = -1
    stack_size: int = 0
    client_buffer: int = 0
    server_buffer: int = 0
    param_count: int = 0
    param_types: list = field(default_factory=list)
    auth_check: str = ""
    error: str = ""

    @property
    def handler_hex(self) -> str:
        return f"0x{self.handler_rva:x}"


@dataclass
class RpcInterface:
    uuid: str
    method_count: int
    syntax: str = "ndr20"
    methods: list = field(default_factory=list)


@dataclass
class PEInfo:
    filename: str
    image_base: int
    sections: list
    import_rva: int
    is_pe32plus: bool = True
