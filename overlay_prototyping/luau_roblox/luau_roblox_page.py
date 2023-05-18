import struct

from .overlay_base import LuauRW_lua_Page
from .overlay_byfron import LuauRWB_lua_Page
from ..base import *

int_to_bytes = lambda x: struct.pack(">I", x)


class LuaPage(object):
    def __init__(self, obj):
        self.lpage = obj
        self.addr = obj.addr
        self.start = obj.addr_of('data')
        self.end = self.start + obj.pageSize
        self.size = self.end - self.addr
        self.objects = {}

    def has_object(self):
        return len(self.objects) > 0

    def is_gco_page(self) -> bool:
        lpage = self.lpage
        return len(self.objects) > 0 or lpage.blockSize == lpage.pageSize or 16360 == lpage.pageSize

    def addr_in(self, addr) -> bool:
        return self.addr <= addr < self.addr + self.size

    def obj_in(self, obj) -> bool:
        return self.lpage.addr <= obj.addr < self.end

    def add_object(self, obj) -> bool:
        if self.obj_in(obj):
            self.objects[obj.addr] = obj
            return True
        return False

    def get_first_object_addr(self) -> int:
        lpage = self.lpage
        return lpage.addr + lpage.pageSize + lpage.freeNext

    def add_obj(self, obj):
        self.objects[obj.addr] = obj

    def add_tvalue(self, tvalue):
        self.objects[tvalue.addr] = tvalue

    def get_block_addrs(self):
        block_size = self.lpage.blockSize
        data_start = self.lpage.addr_of('data')
        data_end = self.lpage.addr + self.lpage.pageSize
        return [i for i in range(data_start, data_end, block_size) if data_start <= i < data_end]


class LuaPages(object):
    def __init__(self):
        self.lpages = {}
        self.pages_by_block_size = {}

    def add_to_pbs(self, lp: LuauRWB_lua_Page | LuauRW_lua_Page):
        if lp is None:
            return
        bs = lp.blockSize
        if bs not in self.pages_by_block_size:
            self.pages_by_block_size[bs] = {}
        self.pages_by_block_size[bs][lp.addr] = lp

    def get_block_sizes(self, bs: int):
        if bs not in self.pages_by_block_size:
            return None
        return sorted(self.pages_by_block_size.keys())

    def get_pages_by_blocksize(self, bs: int):
        if bs not in self.pages_by_block_size:
            return None
        return self.pages_by_block_size[bs]

    def add_obj(self, obj):
        vaddr = obj.addr if obj else None
        if vaddr is None:
            return False
        lp = self.get_page_with_addr(vaddr)
        if lp:
            luapage = self.lpages[lp.addr]
            luapage.add_obj(obj)
            return True
        return False

    def add_tvalue(self, tvalue):
        vaddr = tvalue.addr if tvalue else None
        if vaddr is None:
            return False
        lp = self.get_page_with_addr(vaddr)
        if lp:
            luapage = self.lpages[lp.addr]
            luapage.add_tvalue(tvalue)
            return True
        return False

    def addr_in(self, addr) -> bool:
        for v in self.lpages.values():
            if v.addr_in(addr):
                return True
        return False

    def obj_in(self, obj) -> bool:
        for v in self.lpages.values():
            if v.addr_in(obj.addr):
                return True
        return False

    def get_page_with_addr(self, addr) -> LuauRWB_lua_Page | LuauRW_lua_Page | None:
        for v in self.lpages.values():
            if v.addr_in(addr):
                return v.lpage
        return None

    def get_page_abstraction_with_addr(self, addr) -> LuaPage | None:
        for v in self.lpages.values():
            if v.addr_in(addr):
                return v
        return None

    def get_page_with_obj(self, obj) -> LuauRWB_lua_Page | LuauRW_lua_Page | None:
        addr = obj.addr
        for v in self.lpages.values():
            if v.addr_in(addr):
                return v.lpage
        return None

    def add_page(self, lpage: LuauRWB_lua_Page | LuauRW_lua_Page, walk_pages=False) -> bool:
        if (isinstance(lpage, LuauRWB_lua_Page) or isinstance(lpage, LuauRW_lua_Page)) and lpage.addr not in self.lpages:
            lp = LuaPage(lpage)
            self.lpages[lpage.addr] = lp
            self.add_to_pbs(lpage)
            return True
        return False

    def has_page(self, lpage) -> bool:
        if lpage is not None and self.has_page_addr(lpage.addr):
            return True
        return False

    def has_page_addr(self, addr) -> bool:
        return addr in self.lpages

    def get_known_page_addrs(self) -> list[int]:
        return list(self.lpages.keys())

    def get_pages(self) -> list[LuauRWB_lua_Page | LuauRW_lua_Page]:
        return [l.lpage for l in self.lpages.values()]

    def get_first_object_addr(self, lpage=None, addr=None) -> None | int:
        addr = lpage.addr if addr is None else addr
        if isinstance(addr, int):
            lpage = self.get_page_with_addr(addr)
            if lpage:
                return self.lpages[lpage.addr].get_first_object_addr()
            return None
        elif (isinstance(lpage, LuauRWB_lua_Page) or isinstance(lpage, LuauRW_lua_Page)) and lpage.addr in self.lpages:
            return self.lpages[lpage.addr].get_first_object_addr()
        elif (isinstance(lpage, LuauRWB_lua_Page) or isinstance(lpage, LuauRW_lua_Page)):
            self.add_page(lpage)
            return self.lpages[addr].get_first_object_addr()
        return None
