import ctypes
import string
import threading
from threading import Thread

from .consts import *
from .enumerate_luau_roblox import LuauSifterResults, LuauSifterResult
# from .luau_roblox_base import LuauRobloxBase
from .overlay_base import LuauRW_BaseStruct, LuauRW_TString, LuauRW_lua_State, LuauRW_Udata, LuauRW_Table, \
    LuauRW_UpVal, LuauRW_Closure, VALID_OBJ_CLS_MAPPING, LuauRW_GCHeader, LuauRW_TValue, LuauRW_global_State, \
    LuauRW_lua_Page, LuauRW_ProtoECB
from ..analysis import Analysis, MemRange
from ..base import BaseException

GCO_TT_MAPPING = {
    TSTRING: LuauRW_TString,
    TUPVAL: LuauRW_UpVal,
    TTHREAD: LuauRW_lua_State,
    TCLOSURE: LuauRW_Closure,
    TTABLE: LuauRW_Table,
    # TPROTO: LuauRW_Proto,
    TPROTO: LuauRW_ProtoECB,
    TUSERDATA: LuauRW_Udata
}

GCO_NAME_MAPPING = {
    TSTRING: LuauRW_TString,
    TUPVAL: LuauRW_UpVal,
    TTHREAD: LuauRW_lua_State,
    TCLOSURE: LuauRW_Closure,
    TTABLE: LuauRW_Table,
    # TPROTO: LuauRW_Proto,
    TPROTO: LuauRW_ProtoECB,
    TUSERDATA: LuauRW_Udata,
}


class LuaPage(object):
    def __init__(self, obj):
        self.lpage = obj
        self.addr = obj.addr
        self.start = obj.addr_of('data')
        self.end = self.start + obj.pageSize
        self.size = self.end = self.addr
        self.objects = {}

    def has_object(self):
        return self.objects > 0

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


class LuaPages(object):
    def __init__(self):
        self.lpages = {}
        self.pages_by_block_size = {}

    def add_to_pbs(self, lp: LuauRW_lua_Page):
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
            lp.add_obj(obj)
            return True
        return False

    def add_tvalue(self, tvalue):
        vaddr = tvalue.addr if tvalue else None
        if vaddr is None:
            return False
        lp = self.get_page_with_addr(vaddr)
        if lp:
            lp.add_tvalue(tvalue)
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

    def get_page_with_addr(self, addr) -> LuauRW_lua_Page | None:
        for v in self.lpages.values():
            if v.addr_in(addr):
                return v.lpage
        return None

    def get_page_abstraction_with_addr(self, addr) -> LuaPage | None:
        for v in self.lpages.values():
            if v.addr_in(addr):
                return v
        return None

    def get_page_with_obj(self, obj) -> LuauRW_lua_Page | None:
        addr = obj.addr
        for v in self.lpages.values():
            if v.addr_in(addr):
                return v.lpage
        return None

    def add_page(self, lpage: LuauRW_lua_Page, walk_pages=False) -> bool:
        if isinstance(lpage, LuauRW_lua_Page) and lpage.addr not in self.lpages:
            lp = LuaPage(lpage)
            self.lpages[lpage.addr] = lp
            self.add_to_pbs(lp)
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

    def get_pages(self) -> list[LuauRW_lua_Page]:
        return [l.lpage for l in self.lpages.values()]

    def get_first_object_addr(self, lpage=None, addr=None) -> None | int:
        addr = lpage.addr if addr is None else addr
        if isinstance(addr, int):
            lpage = self.get_page_with_addr(addr)
            if lpage:
                return self.lpages[lpage.addr].get_first_object_addr()
            return None
        elif isinstance(lpage, LuauRW_lua_Page) and lpage.addr in self.lpages:
            return self.lpages[lpage.addr].get_first_object_addr()
        elif isinstance(lpage, LuauRW_lua_Page):
            self.add_page(lpage)
            return self.lpages[addr].get_first_object_addr()
        return None


class LuauRobloxAnalysis(Analysis):

    def __init__(self, sift_results=None, **kargs):
        super(LuauRobloxAnalysis, self).__init__(name="LuauRobloxAnalysis", **kargs)
        self.lrss = None
        self.strings = {}
        self.prims = {}
        self.load_srt = None
        self.analysis_thread = None
        self.analysis_results = None
        if not hasattr(self, 'is_32bit'):
            self.is_32bit = True

        self.raw_sift_results = sift_results
        self.sift_results_loaded = False
        self.anchor_objects = {}
        self.anchor_sections = {}
        self._anchor_mr = {}
        self.objects_by_anchor_section = {}
        self.word_sz = kargs.get('word_sz', 4)
        if self.word_sz is None:
            self.word_sz = 4

        self.lua_gco = {
            k: {} for k in VALID_OBJ_TYPES
        }

        self.lua_gco_by_memcat = {
            k: {} for k in VALID_OBJ_TYPES
        }

        self.printable_strings = {}

        self.lua_structs = {}
        self.not_lua_objects = {k: set() for k in VALID_OBJ_TYPES}

        self.lua_table_values = {}
        self.lua_pages = LuaPages()
        self.valid_lua_gco_pages = []

    def read_table_values(self, ttable: LuauRW_Table, add_obj=False) -> dict[LuauRW_TValue]:
        sizearray = ttable.sizearray
        tvalues = {}
        for idx in range(0, sizearray):
            tva = ttable.get_tvalue_address(idx)
            tvalue = LuauRW_TValue.from_analysis(tva, self)
            tvalues[tvalue.addr] = tvalue
            if add_obj:
                self.add_struct_object(tva, tvalue)
        return tvalues

    def add_gco_to_luapage(self, obj):
        return self.lua_pages.add_obj(obj)

    def add_tvalue_to_luapage(self, tvalue):
        return self.lua_pages.add_tvalue(tvalue)

    def add_gc_object(self, addr, obj, ref_addr=None):
        if obj is None:
            return
        vaddr = obj.addr
        super(LuauRobloxAnalysis, self).add_gc_object(vaddr, obj)

        if obj.is_valid_gc_header():
            tt = obj.get_gch().tt
            self.lua_gco[tt][addr] = obj
            mc = obj.get_gch().memcat
            if mc not in self.lua_gco_by_memcat:
                self.lua_gco_by_memcat[mc] = {}

            if tt not in self.lua_gco_by_memcat[mc]:
                self.lua_gco_by_memcat[mc][tt] = {}

            self.lua_gco_by_memcat[mc][tt][addr] = obj

            refs = self.lrss.gco_srcs.get(addr)
            if refs is not None:
                for ref in refs:
                    raddr = ref['vaddr']
                    self.add_gco_reference(obj, raddr)

    def get_lua_objs_by_memcat(self, memcat, tt=None) -> dict[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata]:
        if memcat is None:
            return self.get_lua_objs(tt=tt)
        objs = {}
        mc_objs = self.lua_gco_by_memcat.get(memcat, {})
        if len(mc_objs) == 0 or tt is not None and tt not in mc_objs:
            return mc_objs

        if tt is None:
            for tt in mc_objs.values():
                objs.update(mc_objs)
        else:
            objs.update(mc_objs[tt])
        return objs

    def get_lua_objs(self, tt=None, memcat=None) -> dict[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata]:
        if memcat is not None:
            return self.get_lua_objs_by_memcat(memcat, tt=tt)

        tts = []
        if tt is None:
            tts = list(self.lua_gco.keys())
        else:
            tts = [tt]
        r = {}
        for tt in tts:
            r.update({k: v for k, v in self.lua_gco[tt].items()})
        return r

    def get_lua_object(self, vaddr,
                       tt=None) -> None | LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata:
        if tt is not None and vaddr in self.lua_gco[tt]:
            return self.lua_gco[tt][vaddr]
        for gcos in self.lua_gco.values():
            if vaddr in gcos:
                return gcos[vaddr]
        return None

    def get_strings(self) -> dict[LuauRW_TString]:
        return self.get_lua_objs(TSTRING)

    def get_udatas(self) -> dict[LuauRW_Udata]:
        return self.get_lua_objs(TUSERDATA)

    def get_closures(self) -> dict[LuauRW_Closure]:
        return self.get_lua_objs(TCLOSURE)

    def get_tables(self) -> dict[LuauRW_Table]:
        return self.get_lua_objs(TTABLE)

    def get_protos(self) -> dict[LuauRW_ProtoECB]:
        return self.get_lua_objs(TPROTO)

    def get_upvals(self) -> dict[LuauRW_UpVal]:
        return self.get_lua_objs(TUPVAL)

    def get_threads(self) -> dict[LuauRW_lua_State]:
        return self.get_lua_objs(TTHREAD)

    def check_results_status(self) -> bool:
        if hasattr(self, 'sift_results_loaded') and self.sift_results_loaded:
            return True
        elif hasattr(self, 'load_srt') and self.load_srt and self.load_srt.is_alive():
            self.log.debug(
                "Still loading. loaded potential gcos from {} and potential structs {} results from {}".format(
                    len(self.lrss.gco_results), len(self.lrss.struct_results), self.raw_sift_results))
            return False
        return self.mark_complete()

    def check_analysis_status(self) -> bool:
        if self.check_results_status() and isinstance(self.analysis_results, dict):
            self.log.debug(
                "Lua Automatic Memory Analysis Completed ".format())
            return True
        return False

    def is_sift_results_loaded(self) -> bool:
        return self.sift_results_loaded

    def scan_lua_pages_gco(self) -> [
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata]:
        lpages = self.lua_pages.get_pages()
        objs = []
        checked = []
        self.valid_lua_gco_pages = []
        for lpage in lpages:
            # evaluate whether this lua_Page is relevant and should be searched
            if any([i[0] < lpage.addr < i[1] for i in checked]):
                self.log.debug("lua_Page already checked, lua_Page @ 0x{:08x} ".format(lpage.addr))
                continue
            elif lpage.pageSize > 0x8000 or lpage.pageSize <= 0:
                self.log.debug(
                    "lua_Page size is incompatible with scan ({}), lua_Page @ 0x{:08x} ".format(hex(lpage.pageSize),
                                                                                                lpage.addr))
                continue
            lpage_start = lpage.addr
            lpage_end = lpage.addr + 24 + lpage.pageSize
            checked.append([lpage_start, lpage_end])
            r = self.scan_lua_page_gco(lpage=lpage)
            if len(r) > 0:
                self.log.debug("Found {} new objects in lua_Page @ 0x{:08x} ".format(len(r), lpage.addr))
                objs = objs + r
                self.valid_lua_gco_pages.append(lpage)
            else:
                self.log.debug("No objects in lua_Page @ 0x{:08x} ".format(lpage.addr))

        self.valid_lua_gco_pages = sorted(self.valid_lua_gco_pages, key=lambda x: x.addr)
        return objs

    def scan_lua_page_gco(self, addr=None, lpage=None, add_object=False, printable_strings=True, incr=4) -> [
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata]:
        objs = []
        if addr is None and lpage is None:
            return objs
        elif addr is None and not isinstance(lpage, LuauRW_lua_Page):
            return objs
        elif lpage is None and isinstance(addr, int):
            lpage_obj = self.lua_pages.get_page_with_addr(addr)
            if lpage_obj is None:
                return objs
            lpage = lpage_obj.lpage

        if lpage is None:
            return objs
        # scanning from the first free object down the page until we stop
        padding = (lpage.addr + lpage.pageSize + lpage.freeNext) % 8
        start_addr = (lpage.addr + lpage.pageSize + lpage.freeNext) + padding
        block_size = lpage.blockSize
        if start_addr < lpage.addr or start_addr <= 0:
            return objs

        pos = 0
        end = lpage.addr + lpage.pageSize
        tables = list(self.get_tables().values())
        self.log.debug("Scanning lua Page @ 0x{:08x} (sz={}) for GCOs".format(lpage.addr, lpage.pageSize))
        while pos + start_addr < end:
            if not self.has_gco(pos + start_addr):
                gco = self.read_gco(pos + start_addr, caution=False)
                if gco is None:
                    pos += incr
                    continue
                r = self.sanity_check(gco, add_obj=add_object, printable_strings=printable_strings, tables=tables)
                if isinstance(r, list) and len(r) > 0:
                    self.log.debug("Found new gco @ 0x{:08x} tt: {} ".format(start_addr + pos, gco.tt))
                    incr = gco.get_total_size()
                    objs.append(gco)
                    if isinstance(gco, LuauRW_Table):
                        tables.append(gco)
            else:
                # this GCO was already known, let's look it up and skip over the size
                gco = self.get_lua_object(start_addr + pos)
                incr = gco.get_total_size()
            pos += incr
        return objs

    def sift_results_load_complete(self) -> dict:
        self.log.debug("Enumerating and checking Lua GCO Tables".format())
        tables = self.potentials_tables(sanity_check=True, add_obj=True)
        self.log.debug("Found {} Lua GCO Tables".format(len(tables)))

        self.log.debug("Enumerating and checking Lua GCO Strings".format())
        tstrings = self.potentials_tstrings(sanity_check=True, add_obj=True, tables=tables)
        self.log.debug("Found {} Lua GCO Strings".format(len(tstrings)))
        self.log.debug("Enumerating and checking Lua GCO Closures".format())
        closures = self.potentials_closures(sanity_check=True, add_obj=True, tables=tables)
        self.log.debug("Found {} Lua GCO Closures".format(len(closures)))

        self.log.debug("Enumerating and checking Lua GCO UserData".format())
        useer_datas = self.potentials_userdatas(sanity_check=True, add_obj=True, tables=tables)
        self.log.debug("Found {} Lua GCO User Data".format(len(useer_datas)))

        self.log.debug("Enumerating and checking Lua GCO Threads".format())
        threads = self.potentials_threads(sanity_check=True, add_obj=True, tables=tables)
        self.log.debug("Found {} Lua GCO Threads".format(len(threads)))

        self.log.debug("Enumerating and checking Lua GCO Prototypes".format())
        prototypes = self.potentials_prototypes(sanity_check=True, add_obj=True, tables=tables)
        self.log.debug("Found {} Lua GCO Prototypes".format(len(prototypes)))

        self.log.debug("Enumerating and checking Lua GCO UpVals".format())
        upvals = self.potentials_upvals(sanity_check=True, add_obj=True, tables=tables)
        self.log.debug("Found {} Lua GCO Upvals".format(len(upvals)))

        self.log.debug("Enumerating and checking Lua Pages".format())
        lpages = self.find_lua_pages()
        self.log.debug("Found {} Lua Pages".format(len(lpages)))

        self.log.debug("Scanning single object allocations on Lua Pages for Objects".format())
        single_blocks = [i.addr for i in lpages if i.busyBlocks == 1]
        self.log.debug("Found {} single block allocation on the pages".format(len(single_blocks)))
        new_gcos = []
        # TODO Scan pages for TValues and LuaNodes
        for sb_addr in single_blocks:
            obj_addr = self.lua_pages.get_first_object_addr(addr=sb_addr)
            gco = self.read_gco(obj_addr)
            if gco and self.has_gco(gco.addr):
                continue
            if gco:
                r = self.sanity_check(gco, add_obj=True, printable_strings=True, tables=tables)
                if r and len(r) > 0:
                    typ = VALID_OBJ_TYPES.get(gco.tt, "UNKNOWN")
                    self.log.debug("Found {} GCO at 0x{:08x}".format(typ, gco.addr))
        # TODO UpVal recognizer
        self.analysis_results = {'unreferenced_gco': new_gcos, "table": tables, "prototype": prototypes,
                                 'lua_State': threads,
                                 "tstring": tstrings, "closures": closures, "userdata": useer_datas, "upvals": upvals}
        self.log.debug("Completed auto analysis for Lua Objects".format())
        return self.analysis_results

    def mark_complete(self, from_callback=False):
        if from_callback or isinstance(self.load_srt, threading.Thread) and not self.load_srt.is_alive():
            self.sift_results_loaded = True
            self.load_srt = None
            self.log.debug(
                "Sift results loading Completed. loaded potential gcos from {} and potential structs {} results from {}".format(
                    len(self.lrss.gco_results), len(self.lrss.struct_results), self.raw_sift_results))
        return self.sift_results_loaded

    def thread_completed(self):
        self.log.debug("Sift results loading Completed.")
        self.mark_complete(from_callback=True)
        self.log.debug("Starting the analysis thread")
        self.analysis_thread = threading.Thread(target=self.sift_results_load_complete)
        self.analysis_thread.start()

    def load_sift_results(self, pointer_file=None, background=True, bulk_load=True) -> bool:
        if self.raw_sift_results is None and pointer_file is None:
            raise BaseException("No sift results file set")

        if self.load_srt is not None:
            return self.check_results_status()

        if self.raw_sift_results is None:
            self.raw_sift_results = pointer_file

        self.log.debug("Loading luau-sifter results from {}".format(self.raw_sift_results))
        self.lrss = LuauSifterResults()
        kwargs = {'parse_gc_header': False, 'bulk_load': bulk_load, 'callback': self.thread_completed}
        self.load_srt = Thread(target=self.lrss.parse_file, kwargs=kwargs, args=(self.raw_sift_results,))
        self.load_srt.start()
        if not background:
            self.load_srt.join()
        return self.check_results_status()

    def get_gco_overlay(self, vaddr, ctypes_cls, buf=None, ref_addr=None, add_obj=False,
                        caution=False) -> None | LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata:
        ett = getattr(ctypes_cls, '_tt_', None)
        if ett is None or not ctypes_cls.has_gc_header() or vaddr in self.not_lua_objects[ett]:
            return None

        obj_sz = ctypes.sizeof(ctypes_cls)
        buf = self.read_vaddr(vaddr, obj_sz) if buf is None or len(buf) != obj_sz else buf
        if len(buf) != obj_sz and not caution:
            self.not_lua_objects[ett].add(vaddr)
            return None
        elif len(buf) != obj_sz:
            self.not_lua_objects[ett].add(vaddr)
            raise BaseException("Unable to read the buffer of right size for {}".format(str(ctypes_cls)))

        gco = ctypes_cls.from_bytes(addr=vaddr, buf=buf, analysis=self)
        vgch = gco.is_valid_gc_header()
        if not vgch and caution:
            self.not_lua_objects[ett].add(vaddr)
            raise BaseException("Object {} has invalid header: {}".format(str(ctypes_cls), gco))
        elif not vgch:
            self.not_lua_objects[ett].add(vaddr)
            return None

        if add_obj:
            self.add_gc_object(vaddr, gco, ref_addr=ref_addr)
        return gco

    def get_overlay_obj_at(self, ctypes_cls, vaddr, ref_vaddr=None, add_obj=False, caution=False):
        if ctypes_cls is None:
            return None

        if ctypes_cls.has_gc_header():
            return self.get_gco_overlay(vaddr, ctypes_cls, ref_addr=ref_vaddr, add_obj=add_obj, caution=caution)

        obj_sz = ctypes.sizeof(ctypes_cls)
        buf = self.read_vaddr(vaddr, obj_sz)

        if len(buf) != obj_sz and not caution:
            return None
        elif len(buf) != obj_sz:
            raise BaseException("Unable to read the buffer for {}".format(str(ctypes_cls)))

        obj = ctypes_cls.from_bytes(addr=vaddr, buf=buf, analysis=self)
        if obj is None and not caution:
            return None
        elif obj is None:
            raise BaseException("Unable to read the buffer for {}".format(str(ctypes_cls)))

        if add_obj:
            self.add_struct_object(vaddr, obj)
            refs = self.lrss.gco_srcs.get(vaddr)
            if refs is not None:
                for ref in refs:
                    raddr = ref['vaddr']
                    self.add_gco_reference(obj, raddr)

        return obj

    def add_string_at_vaddr(self, vaddr, ref_vaddr=None) -> None | LuauRW_TString:
        obj = self.get_lua_object(vaddr, TSTRING)
        if obj is not None and obj.is_string():
            return obj
        data = self.read_vaddr(vaddr, self.DEFAULT_OBJECT_READ_SZ)
        s = LuauRW_TString.from_bytes(vaddr, data, analysis=self, word_sz=self.word_sz)
        if s is not None and s.is_valid_gc_header() and s.get_gch().tt == TSTRING:
            self.add_gc_object(s.addr, s, ref_vaddr)
            nvaddr = s.next
            if nvaddr != 0x0:
                _ = self.add_string_at_vaddr(s.next, s.addr_of("next"))
                # self.add_gc_object(nv.addr, nv, s.addr_of("next"))
        return s

    def bad_obj_address(self, addr):
        for v in self.not_lua_objects.values():
            v.add(addr)

    def read_gco(self, vaddr, tt=None, add_obj=False,
                 caution=False) -> None | LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata:
        if tt is None:
            gco = None
            try:
                gco = LuauRW_GCHeader.from_analysis(vaddr, self)
            except:
                if caution:
                    raise
            if gco is not None:
                tt = gco.tt
            # else:
            #     self.bad_obj_address(vaddr)

        if tt not in VALID_OBJ_CLS_MAPPING:
            return None
        elif vaddr in self.not_lua_objects[tt]:
            return None

        cls = VALID_OBJ_CLS_MAPPING.get(tt)
        return self.get_gco_overlay(vaddr, cls, add_obj=add_obj, caution=caution)

    def read_tvalue(self, vaddr, index=0, add_obj=False, caution=False) -> None | LuauRW_TValue:
        tv = LuauRW_TValue.from_analysis(vaddr, self)
        return tv

    def read_gco_ptr(self, pvaddr, tt=None, word_sz=4, little_endian=True, add_obj=False,
                     caution=False) -> None | LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata:
        if tt is None:
            vaddr = self.deref_address(pvaddr, word_sz, little_endian)
            if vaddr is None:
                self.bad_obj_address(pvaddr)
                return None
            gco = LuauRW_GCHeader.from_analysis(vaddr, self)
            if gco is not None:
                tt = gco.tt
            else:
                self.bad_obj_address(vaddr)

        if tt not in VALID_OBJ_CLS_MAPPING:
            return None
        elif vaddr in self.not_lua_objects[tt]:
            return None

        cls = VALID_OBJ_CLS_MAPPING.get(tt)
        return self.get_gco_overlay(vaddr, cls, ref_addr=pvaddr, add_obj=add_obj, caution=caution)

    def read_struct_ptr(self, pvaddr: int, obj_cls: LuauRW_BaseStruct, word_sz=4, little_endian=True,
                        add_obj=False) -> object | None:
        if obj_cls.is_gco():
            return self.read_gco_ptr(pvaddr, obj_cls._tt_, word_sz, little_endian, add_obj)

        vaddr = self.deref_address(pvaddr, word_sz, little_endian)
        if vaddr is None:
            return None

        obj = obj_cls.from_analysis(vaddr, self)
        if obj is not None and obj.sanity_check() and add_obj:
            self.add_gc_object(vaddr, obj, pvaddr)
        return obj

    def find_lua_strings_from_sift_file(self) -> dict[LuauRW_TString]:
        if not self.memory_loaded:
            self.load_memory()

        if not self.sift_results_loaded:
            self.load_sift_results()

        return self.get_strings_from_sifter_results()

    def get_potential_objects_from_sifter(self, tt, perform_overlay=True, add_obj=False) -> list[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata]:
        results = []
        for o in self.lrss.get_potential_objects():
            # this is a sifter result and not an object
            if o.is_valid_gc_header() and o.tt == tt:
                if perform_overlay:
                    cls_type = VALID_OBJ_CLS_MAPPING.get(tt)
                    obj = self.get_gco_overlay(o.sink_vaddr, cls_type, add_obj=add_obj)
                    if obj is not None:
                        results.append(obj)
                else:
                    results.append(o)
        return results

    def sanity_check(self, obj, add_obj=False, printable_strings=False, tables=None) -> list[
        None | LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata]:
        tables = tables if tables else list(self.get_tables().values())
        if obj.tt == TSTRING:
            return self.sanity_check_tstrings([obj], add_obj=add_obj, printable_strings=printable_strings)
        elif obj.tt == TCLOSURE:
            return self.sanity_check_closures([obj], add_obj=add_obj, tables=tables)
        elif obj.tt == TTABLE:
            return self.sanity_check_tables([obj], add_obj=add_obj)
        elif obj.tt == TUSERDATA:
            return self.sanity_check_userdatas([obj], add_obj=add_obj, tables=tables)
        elif obj.tt == TTHREAD:
            return self.sanity_check_threads([obj], add_obj=add_obj, tables=tables)
        elif obj.tt == TPROTO:
            return self.sanity_check_protos([obj], add_obj=add_obj, tables=tables)
        elif obj.tt == TUPVAL:
            return self.sanity_check_upvals([obj], add_obj=add_obj)
        return None

    def sanity_check_tstrings(self, tstring_list, add_obj=False, printable_strings=False) -> list[LuauRW_TString]:
        tstrings = []
        for obj in tstring_list:
            if not self.check_string(obj, printable_string=False):
                continue

            tstrings.append(obj)
            self.strings[obj.addr] = obj
            value = None if not isinstance(obj, LuauRW_TString) else obj.get_value()
            if printable_strings and value is not None and self.is_printable_string(value):
                self.printable_strings[obj.addr] = obj

        if add_obj:
            for o in tstrings:
                self.add_gc_object(o.addr, o)

        if printable_strings:
            tstrings = list(self.printable_strings.values())
        return tstrings

    def potentials_tstrings(self, sanity_check=False, add_obj=False, printable_strings=True, tables=None) -> list[
        LuauRW_TString]:
        r = self.get_potential_objects_from_sifter(TSTRING)
        if sanity_check:
            return self.sanity_check_tstrings(r, add_obj=add_obj, printable_strings=printable_strings)
        return r

    def sanity_check_closures(self, closeure_list, add_obj=False, tables=None) -> list[LuauRW_Closure]:
        if tables is None:
            tables = self.potentials_tables(sanity_check=True, add_obj=add_obj)
        dt = {t.addr: t for t in tables}
        closures = []
        for obj in closeure_list:
            if obj.env in dt:
                closures.append(obj)
        if add_obj:
            for o in closures:
                self.add_gc_object(o.addr, o)
        return closures

    def potentials_closures(self, sanity_check=False, add_obj=False, tables=None) -> list[LuauRW_Closure]:
        r = self.get_potential_objects_from_sifter(TCLOSURE)
        if sanity_check:
            self.sanity_check_closures(r, add_obj=add_obj, tables=tables)
        return r

    def sanity_check_userdatas(self, userdata_list, add_obj=False, tables=None) -> list[LuauRW_Udata]:
        userdatas = []
        if tables is None:
            tables = self.potentials_tables(sanity_check=True, add_obj=add_obj)
        dt = {t.addr: t for t in tables}
        for obj in userdata_list:
            if obj.metatable in dt:
                userdatas.append(obj)
        if add_obj:
            for o in userdatas:
                self.add_gc_object(o.addr, o)
        return userdatas

    def potentials_userdatas(self, sanity_check=False, add_obj=False, tables=None) -> list[LuauRW_Udata]:
        r = self.get_potential_objects_from_sifter(TUSERDATA)
        if sanity_check:
            return self.sanity_check_userdatas(r, add_obj=add_obj, tables=tables)
        return r

    def sanity_check_threads(self, thread_list, add_obj=False, tables=None) -> list[LuauRW_lua_State]:
        threads = []
        dt = {t.addr: t for t in thread_list}
        if tables is None:
            tables = self.potentials_tables(sanity_check=True, add_obj=add_obj)
        dtables = {t.addr: t for t in tables}
        for obj in dt.values():
            global_state = self.valid_vaddr(getattr(obj, 'global'))
            call_info = self.valid_vaddr(obj.ci)
            stack = self.valid_vaddr(obj.stack)
            stack_last = self.valid_vaddr(obj.stack_last)
            gt = self.valid_vaddr(obj.gt) and obj.gt in dtables
            all_checks = [global_state, call_info, stack, stack_last, gt]
            if all(all_checks):
                threads.append(obj)
        if add_obj:
            for o in threads:
                self.add_gc_object(o.addr, o)
        return threads

    def potentials_threads(self, sanity_check=False, add_obj=False, tables=None) -> list[LuauRW_lua_State]:
        r = self.get_potential_objects_from_sifter(TTHREAD)
        if sanity_check:
            self.sanity_check_threads(r, add_obj=add_obj, tables=tables)
        return r

    def sanity_check_tables(self, tables_list, add_obj=False) -> list[LuauRW_Table]:
        tables = {}
        dt = {i.addr: i for i in tables_list}
        for t in dt.values():
            if self.valid_vaddr(t.metatable) and t.metatable in dt:
                tables[t.addr] = t
                tables[t.metatable] = t
        tables = list(tables.values())
        if add_obj:
            for o in tables:
                self.add_gc_object(o.addr, o)
        return tables

    def potentials_tables(self, sanity_check=False, add_obj=False) -> list[LuauRW_Table]:
        r = self.get_potential_objects_from_sifter(TTABLE)
        if sanity_check:
            return self.sanity_check_tables(r, add_obj=add_obj)
        return r

    def sanity_check_protos(self, protos_list, add_obj=False, check_execdata=True, tables=None) -> list[
        LuauRW_ProtoECB]:
        v_k = lambda p: p.k == 0 or self.valid_vaddr(p.k)
        v_code = lambda p: p.code > 0 and self.valid_vaddr(p.code)
        v_p = lambda p: p.p == 0 or self.valid_vaddr(p.p)
        v_lineinfo = lambda p: p.lineinfo == 0 or self.valid_vaddr(p.lineinfo)
        v_locvars = lambda p: p.locvars == 0 or self.valid_vaddr(p.locvars)
        v_source = lambda p: p.source == 0 or self.valid_vaddr(p.source)
        v_debugname = lambda p: p.debugname == 0 or self.valid_vaddr(p.debugname)
        v_debuginsn = lambda p: p.debuginsn == 0 or self.valid_vaddr(p.debuginsn)

        checks = [
            v_k, v_code, v_p, v_lineinfo, v_locvars, v_source, v_debugname, v_debuginsn,
        ]
        if check_execdata:
            v_execdata = lambda p: p.execdata == 0 or self.valid_vaddr(p.execdata) \
                if isinstance(p, LuauRW_ProtoECB) else True
            checks.append(v_execdata)
        protos = {}
        for p in protos_list:
            if p.addr in protos:
                continue
            if all([fn(p) for fn in checks]):
                protos[p.addr] = p

        lprotos = list(protos.values())
        if add_obj:
            for p in lprotos:
                self.add_gc_object(p.addr, p)
        return lprotos

    def potentials_prototypes(self, sanity_check=False, add_obj=False, check_execdata=True, tables=None) -> list[
        LuauRW_ProtoECB]:
        r = self.get_potential_objects_from_sifter(TPROTO)
        if sanity_check:
            return self.sanity_check_protos(r, add_obj=add_obj, check_execdata=check_execdata, tables=tables)
        return r

    def sanity_check_upvals(self, upvals_list, add_obj=False) -> list[LuauRW_UpVal]:
        upvals = []
        for obj in upvals_list:
            if self.valid_vaddr(obj.v):
                tvalue = LuauRW_TValue.from_analysis(obj.v, self)
                if tvalue and tvalue.tt in LUA_TAG_TYPES:
                    upvals.append(obj)
        if add_obj:
            for o in upvals:
                self.add_gc_object(o.addr, o)
        return upvals

    def potentials_upvals(self, sanity_check=False, add_obj=False, tables=None) -> list[LuauRW_UpVal]:
        r = self.get_potential_objects_from_sifter(TUPVAL)
        if sanity_check:
            return self.sanity_check_upvals(r, add_obj=add_obj)
        return r

    def find_potential_global_state(self, pot_threads=None) -> dict[LuauRW_global_State]:
        globals_results = {}
        pot_threads = self.potentials_threads() if pot_threads is None else pot_threads
        gs_addrs = {getattr(i, 'global'): i for i in pot_threads if
                    i is not None and self.valid_vaddr(getattr(i, 'global'))}

        global_states = [LuauRW_global_State.from_analysis(i, self, safe_load=False) for i in gs_addrs]
        global_states = [i for i in global_states if i is not None]
        for gs in global_states:
            frealloc = gs.frealloc > 0 or self.valid_vaddr(gs.frealloc)
            gray = gs.gray > 0 or self.valid_vaddr(gs.gray)
            grayagain = gs.grayagain > 0 or self.valid_vaddr(gs.grayagain)
            weak = gs.weak > 0 or self.valid_vaddr(gs.weak)
            allgcopages = gs.allgcopages > 0 or self.valid_vaddr(gs.allgcopages)
            mainthread = gs.mainthread > 0 or self.valid_vaddr(gs.mainthread)
            # mainthread_in_threads = mainthread in gs_addrs # and gs_addrs[mainthread] == gs
            all_checks = [frealloc, gray, grayagain, weak, allgcopages, mainthread, ]
            if all(all_checks):
                globals_results[gs.addr] = gs
        return globals_results

    # @classmethod
    # def create_class(cls, name, overlay):
    #     return LuauRobloxBase.create_overlay(name, overlay, bases=(LuauRobloxBase,))

    # def create_object_at(self, name, overlay, vaddr, sz=8192):
    #     cls = LuauRobloxBase.create_overlay(name, overlay)
    #     data = self.read_vaddr(vaddr, sz)
    #     return cls.from_bytes(vaddr, data, self, self.is_32bit)

    def get_memrange(self, vaddr) -> MemRange:
        return self.mem_ranges.get_memrange_from_vaddr(vaddr)

    def get_objects_in_section(self, vaddr) -> list[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata]:
        results = []
        mr = self.get_memrange(vaddr)
        if mr is None:
            return results

        for v in self.get_object_addresses():
            addr = v.sink_vaddr
            if mr.start <= addr < mr.end:
                results.append(v)
        return results

    def get_pot_objects_in_section(self, vaddr) -> list[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata]:
        results = []
        mr = self.get_memrange(vaddr)
        if mr is None:
            return results
        pot_objects = self.lrss.get_potential_objects()
        for v in pot_objects:
            if not v.is_valid_gc_header():
                continue
            addr = v.sink_vaddr
            if mr.start <= addr < mr.end:
                results.append(v)
        return results

    def get_sinks_in_section(self, vaddr) -> list[int]:
        results = []
        mr = self.get_memrange(vaddr)
        if mr is None:
            return results
        sinks = self.lrss.gco_results.values()
        for v in sinks:
            addr = v.sink_vaddr
            if mr.start <= addr < mr.end:
                results.append(v)
        return results

    def get_srcs_in_section(self, vaddr) -> list[dict]:
        results = []
        mr = self.get_memrange(vaddr)
        if mr is None:
            return results
        sinks = self.lrss.gco_results.items()
        for k, v in sinks:
            addr = k
            if mr.start <= addr < mr.end:
                results.append(v)
        return results

    def get_strings_from_sifter_results(self) -> dict[LuauRW_TString]:
        pot_tstrings = self.lrss.get_potential_tstrings()
        for ts in pot_tstrings:
            vaddr = ts.sink_vaddr
            if vaddr in self.strings:
                continue
            ref_vaddr = ts.vaddr
            self.add_string_at_vaddr(vaddr, ref_vaddr=ref_vaddr)
        return self.get_strings()

    def get_builtin_strings_from_sifter_results(self) -> dict[LuauRW_TString]:
        pot_tstrings = self.lrss.get_potential_tstrings()
        for ts in pot_tstrings:
            vaddr = ts.sink_vaddr
            if vaddr in self.strings:
                continue
            ref_vaddr = ts.vaddr
            if ts.tt != 0x09:
                continue
            self.add_string_at_vaddr(vaddr, ref_vaddr=ref_vaddr)
        return self.get_strings()

    def find_anchor_strings(self) -> dict[LuauRW_TString]:
        if not self.is_sift_results_loaded():
            self.load_sift_results()
        lua_strings = self.get_safe_strings()

        anchor_objects = {}
        for s in lua_strings.values():
            value = None if not isinstance(s, LuauRW_TString) else s.get_value()
            if len(str(value)) == 0:
                continue
            if value in LUAR_ROBLOX_TYPES or value in LUAR_ROBLOX_EVENT_NAMES:
                anchor_objects[s.addr] = s

        self.anchor_objects.update(anchor_objects)
        return anchor_objects

    def find_anchor_objects(self) -> dict[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata]:
        self.anchor_objects = {}
        if not self.is_sift_results_loaded():
            self.load_sift_results()

        # lua_strings
        self.find_anchor_strings()
        self.find_anchor_pages()

        # now that we have anchor pages
        # find all gco threads
        return self.anchor_objects

    def find_printable_strings(self) -> list[LuauRW_TString]:
        pstrings = []
        tstrings = self.potentials_tstrings(sanity_check=True, printable_strings=True)
        for obj in tstrings:
            value = None if not isinstance(obj, LuauRW_TString) else obj.get_value()
            if all([i in string.printable for i in value]):
                pstrings.append(obj)
        return pstrings

    def is_printable_string(self, value) -> bool:
        return value is not None and all([i in string.printable for i in value])

    def check_string(self, obj, printable_string=False) -> bool:
        if printable_string and obj.addr in self.printable_strings:
            return True
        elif not printable_string and obj.addr in self.strings:
            return True

        if not self.valid_vaddr(obj.end) or obj.end < obj.addr:
            return False
        value = None if not isinstance(obj, LuauRW_TString) else obj.get_value()
        if value is None or len(value) > MAXSSIZE:
            return False
        elif printable_string and not self.is_printable_string(value):
            return False
        return True

    def get_safe_strings(self, rerun=True) -> dict[LuauRW_TString]:
        if not rerun:
            return self.printable_strings
        lua_strings = self.potentials_tstrings(sanity_check=True, printable_strings=True, add_obj=True)
        return {o.addr: o for o in lua_strings}

    def get_objects_in_anchor_section(self, obj_tt=None) -> [LuauSifterResult]:
        results = []
        if len(self.anchor_sections) == 0:
            self.find_anchor_pages()

        pot_objects = self.get_potential_objects_from_sifter(obj_tt)
        mrs = [i['memory_range'] for i in self.anchor_sections.values()]
        results = [i for i in pot_objects if any([mr.vaddr <= i.addr < mr.vaddr + mr.vsize for mr in mrs])]
        return results

    def enumerate_objects_in_anchor_sections(self):
        lua_strings = self.get_strings_from_sifter_results()
        for base_vaddr, as_json in self.anchor_sections.items():
            mr = as_json['memory_range']
            self.objects_by_anchor_section[base_vaddr] = {'object_vaddrs': {}, 'memory_range': mr}
            addrs = [k for k in self.get_object_addresses() if mr.vaddr_in_range(k)]
            self.objects_by_anchor_section[base_vaddr]['object_vaddrs'] = set(addrs)
            self.objects_by_anchor_section[base_vaddr]['objects'] = {a: self.get_object(a) for a in addrs}
            self.objects_by_anchor_section[base_vaddr]['strings'] = {a: self.get_object(a) for a in addrs}
        return self.objects_by_anchor_section

    def find_anchor_pages(self) -> dict[MemRange]:
        ao_dict = self.find_anchor_strings()
        for ao in ao_dict.values():
            vaddr = ao.addr
            mr = self.get_memrange(vaddr)
            if mr is None:
                continue
            self.add_anchor_section(mr, vaddr, ao)
            self._anchor_mr[mr.vaddr] = mr
        return self.anchor_sections

    def add_anchor_section(self, mr, vaddr, obj):
        if mr is None:
            return
        base_vaddr = mr.vaddr
        if base_vaddr not in self.anchor_sections:
            self.anchor_sections[base_vaddr] = {"memory_range": mr, 'cnt': 0, 'objects': {}}

        if obj is None:
            return

        self.anchor_sections[base_vaddr]['objects'][vaddr] = obj
        self.anchor_sections[base_vaddr]['cnt'] = len(self.anchor_sections[base_vaddr]['objects'])

    def in_anchor_section(self, vaddr) -> bool:
        for base, mr in self._anchor_mr:
            if mr.vaddr_in_range(vaddr):
                return True
        return False

    def get_anchor_section(self, vaddr) -> None | MemRange:
        for base, mr in self._anchor_mr:
            if mr.vaddr_in_range(vaddr):
                return mr
        return None

    def read_sequential_gcos_incr(analysis, start_addr, allowed_failures=0, stop_addr=None) -> dict:
        gcos = {}
        stop = False

        next_addr = start_addr
        last_gco = None
        failed = allowed_failures
        while not stop:
            try:
                gco = analysis.get_lua_object(next_addr) if analysis.has_gco(next_addr) else analysis.read_gco(
                    next_addr)


            except:
                gco = None

            if failed <= 0:
                break

            if gco is None:
                failed += -1
                _next_addr = next_addr + 8 if next_addr % 8 == 0 else next_addr + (next_addr % 8)
                print("Failed at 0x{:08x}, advancing to 0x{:08x}".format(next_addr, _next_addr))
                next_addr = _next_addr
                continue
            else:
                failed = allowed_failures

            last_gco = gco
            gcos[gco.addr] = gco
            # _next_addr = gco.get_next_gco()
            _next_addr = next_addr + 8 if next_addr % 8 == 0 else next_addr + (next_addr % 8)
            next_addr = _next_addr
            if isinstance(stop_addr, int) and stop_addr >= next_addr:
                break

        stop_addr = next_addr
        return {'gcos': sorted(gcos, key=lambda i: i.addr), "stop_addr": stop_addr}

    def read_sequential_gcos_decrement(self, start_addr, allowed_failures=3, stop_addr=None, block_size=32) -> dict:
        gcos = {}
        stop = False

        next_addr = start_addr if start_addr % 8 == 0 else start_addr - (start_addr % 8)
        last_gco = None
        failed = allowed_failures
        failures = []
        while not stop:
            try:
                gco = self.get_lua_object(next_addr) if self.has_gco(next_addr) else self.read_gco(next_addr)
            except:
                gco = None

            if failed <= 0:
                break
            value = self.read_uint(next_addr)
            if value == 0:
                _next_addr = next_addr - 8
                next_addr = _next_addr
                continue
            elif gco is None:
                failed += -1
                _next_addr = next_addr - 8
                failures.append(next_addr)
                print("Failed at 0x{:08x}, advancing to 0x{:08x}".format(next_addr, _next_addr))
                next_addr = _next_addr
                continue
            else:
                failed = allowed_failures

            gcos[gco.addr] = gco
            # _next_addr = gco.get_next_gco()
            _next_addr = next_addr - block_size
            next_addr = _next_addr
            if isinstance(stop_addr, int) and stop_addr >= next_addr:
                break

        stop_addr = next_addr
        return {'gcos': sorted(gcos.values(), key=lambda i: i.addr), "stop_addr": stop_addr, "failures": failures}

    def find_lua_pages(self) -> list[LuauRW_lua_Page]:
        bsz_0x20 = []
        for s in self.printable_strings.values():
            start_addr = s.addr
            block_size = s.get_next_gco() - s.addr
            if block_size == 0x20:
                bsz_0x20.append(s)

        for s in bsz_0x20:
            if self.lua_pages.obj_in(s):
                continue
            lpage = self.find_lua_page_header(start_addr=s.addr)
            if lpage is None or self.lua_pages.has_page(lpage):
                continue
            _ = self.walk_lua_pages(lpage)
        return list(self.lua_pages.get_pages())

    def walk_lua_page_gcolist_forward(self, lua_page) -> list[LuauRW_lua_Page]:
        # walk GCO List forward
        lua_pages = []
        self.log.debug(
            "Walking the lua_Page linked lists forward from at 0x{:08x}".format(lua_page.gcolistnext))
        nlp = lua_page
        while True:
            if nlp is None or nlp.gcolistnext == 0 or \
                    not self.valid_vaddr(nlp.gcolistnext):
                break
            nlp = LuauRW_lua_Page.from_analysis(nlp.gcolistnext, analysis=self, safe_load=False)
            if self.lua_pages.has_page(nlp):
                break
            if nlp is not None:
                self.lua_pages.add_page(nlp)
                lua_pages.append(nlp)
        return lua_pages

    def walk_lua_page_freelist_forward(self, lua_page) -> list[LuauRW_lua_Page]:
        # walk GCO List forward
        lua_pages = []
        self.log.debug(
            "Walking the lua_Page linked lists forward from at 0x{:08x}".format(lua_page.next))
        nlp = lua_page
        while True:
            if nlp is None or nlp.next == 0 or \
                    not self.valid_vaddr(nlp.next):
                break
            nlp = LuauRW_lua_Page.from_analysis(nlp.next, analysis=self, safe_load=False)
            if self.lua_pages.has_page(nlp):
                break
            if nlp is not None:
                self.lua_pages.add_page(nlp)
                lua_pages.append(nlp)
        return lua_pages

    def walk_lua_page_freelist_backward(self, lua_page) -> list[LuauRW_lua_Page]:
        # walk GCO List forward
        lua_pages = []
        self.log.debug(
            "Walking the lua_Page linked lists forward from at 0x{:08x}".format(lua_page.prev))
        nlp = lua_page
        while True:
            if nlp is None or nlp.prev == 0 or \
                    not self.valid_vaddr(nlp.prev):
                break
            nlp = LuauRW_lua_Page.from_analysis(nlp.prev, analysis=self, safe_load=False)
            if self.lua_pages.has_page(nlp):
                break
            if nlp is not None:
                self.lua_pages.add_page(nlp)
                lua_pages.append(nlp)
        return lua_pages

    def walk_lua_page_gcolist_backward(self, lua_page) -> list[LuauRW_lua_Page]:
        lua_pages = []
        # walk GCO List backward
        self.log.debug(
            "Walking the lua_Page linked lists backward from at 0x{:08x}".format(lua_page.gcolistprev))
        nlp = lua_page
        while True:
            if nlp is None or nlp.gcolistprev == 0 or \
                    not self.valid_vaddr(nlp.gcolistprev):
                break
            nlp = LuauRW_lua_Page.from_analysis(nlp.gcolistprev, analysis=self, safe_load=False)
            if self.lua_pages.has_page(nlp):
                break
            if nlp is not None:
                self.lua_pages.add_page(nlp)
                lua_pages.append(nlp)
        return lua_pages

    def walk_lua_pages(self, lua_page) -> list[LuauRW_lua_Page]:
        '''
        walk the lua pages to find the allocations
        :param lua_page:
        :return:
        '''
        self.lua_pages.add_page(lua_page)
        if lua_page is not None:
            flua_pages = self.walk_lua_page_gcolist_forward(lua_page)
            blua_pages = self.walk_lua_page_gcolist_backward(lua_page)
            already_visited = set(self.lua_pages.get_known_page_addrs())
            # enumerate any new pages froom the ones that were found
            self.log.debug("Reviewing results and looking for undiscovered links in lists")
            not_visited_pages = set()
            for nlp in flua_pages + blua_pages:
                if nlp.gcolistprev > 0 and nlp.gcolistprev not in already_visited:
                    not_visited_pages.add(nlp.gcolistprev)
                if nlp.gcolistnext > 0 and nlp.gcolistnext not in already_visited:
                    not_visited_pages.add(nlp.gcolistprev)
                if nlp.next > 0 and nlp.next not in already_visited:
                    not_visited_pages.add(nlp.next)
                if nlp.prev > 0 and nlp.prev not in already_visited:
                    not_visited_pages.add(nlp.prev)

            not_visited_pages = list(not_visited_pages)
            self.log.debug("found {} unvisited lua pages".format(len(not_visited_pages)))
            # performing page discovery on the new pages
            while len(not_visited_pages) > 0:
                nla = not_visited_pages.pop()
                already_visited.add(nla)
                if nla == 0 or self.lua_pages.has_page_addr(nla) or not self.valid_vaddr(nla):
                    continue
                nlp = LuauRW_lua_Page.from_analysis(nla, analysis=self, safe_load=False)
                more_pages = self.walk_lua_pages(nlp)
                mp = [i.addr for i in more_pages if i.addr not in already_visited]
                not_visited_pages = not_visited_pages + mp
        return list(self.lua_pages.get_pages())

    def find_lua_page_header(self, start_addr=None, allowed_failures=3, stop_addr=None,
                             block_size=32) -> LuauRW_lua_Page:
        lua_page = None
        self.log.debug("Searching for lua_pages using 32-byte sizeclass page")
        if start_addr == None:
            self.log.debug("No start address specified, so using known internal type strings")
            tstrings = self.get_strings()
            astrs = [o for o in tstrings.values() if o.get_value() in LUAR_ROBLOX_EVENT_NAMES]
            astrs = sorted(astrs, key=lambda a: a.addr)
            start_addr = astrs[0].addr

        self.log.debug("Scanning memory segment backwards starting at address: 0x{:08x}".format(start_addr))
        gco_page_scan = self.read_sequential_gcos_decrement(start_addr, allowed_failures=allowed_failures,
                                                            block_size=block_size)
        pot_page_addr = gco_page_scan['stop_addr']
        end_addr = start_addr
        if len(gco_page_scan['gcos']) > 0:
            end_addr = gco_page_scan['gcos'][0].addr
        else:
            self.log.debug(
                "No gcos found in the page, suspect using start address for end of search: 0x{:08x}".format(start_addr))

        # adding some wiggle room to find the page.  also making sure address falls on the 8-byte boundary
        pot_page_addr = pot_page_addr - ctypes.sizeof(LuauRW_lua_Page)
        pot_page_addr = pot_page_addr if pot_page_addr % 8 == 0 else pot_page_addr - (pot_page_addr % 8)

        self.log.debug(
            "Searching for the Luau lua_Page header between 0x{:08x} and 0x{:08x}".format(pot_page_addr, end_addr))

        while pot_page_addr < end_addr:
            lua_page = LuauRW_lua_Page.from_analysis(pot_page_addr, analysis=self, safe_load=False)
            if lua_page.pageSize == 0x3fe8 and lua_page.blockSize == 32:
                self.log.debug(
                    "Found a potential lua_Page header at 0x{:08x}".format(lua_page.addr))
                break
            else:
                lua_page = None
            pot_page_addr += 8
        return lua_page

    def get_last_page_block(self, lua_page: LuauRW_lua_Page) -> None | int:
        if lua_page is None:
            return None

        offset = lua_page.freeNext + lua_page.get_offset('data') + lua_page.blockSize
        return lua_page.addr + offset

    def find_tvalues_in_lua_pages(self, add_obj=False):
        lua_pages = self.lua_pages.get_pages()
        pot_gco = {}
        pot_tval = {}
        pot_tt = {}
        results = {'pot_gco': pot_gco, "pot_tval": pot_tval, 'pot_tt': pot_tt}
        for lp in lua_pages:
            self.log.debug(
                "Scanning lua_Page {:08x} of size: {} for tvalues".format(lp.addr, lp.pageSize))
            x = self.find_tvalues_in_lua_page(lp)
            pot_gco.update(x['pot_gco'])
            pot_tval.update(x['pot_tval'])
            for tt in x['pot_tt'].keys():
                if tt not in pot_tt:
                    pot_tt[tt] = []
                pot_tt[tt] = pot_tt[tt] + x['pot_tt'][tt]
        return results

    def find_tvalues_in_lua_page(self, lp: LuauRW_lua_Page, add_obj=False):
        pot_gco = {}
        pot_tval = {}
        pot_tt = {k: [] for k in LUA_TAG_TYPES}
        results = {'pot_gco': pot_gco, "pot_tval": pot_tval, 'pot_tt': pot_tt}
        if lp.pageSize != 0x3fe8:
            return results

        end = lp.addr + lp.get_offset('data')
        # skip to the end of the page
        vaddr = end + lp.pageSize - ctypes.sizeof(LuauRW_TValue)
        incr = - self.word_sz
        tt_offset = LuauRW_TValue.get_offset("tt")
        a_lp = self.lua_pages.get_page_abstraction_with_addr(lp.addr)
        if a_lp is None:
            self.log.debug("Unable to associate the gcos and tvalues with with a lua_Page ".format())

        while end <= vaddr:
            tt = self.read_uint(vaddr + 12)
            gc_addr = self.read_uint(vaddr)
            if tt not in LUA_TAG_TYPES:
                vaddr += incr
                continue

            tvalue = LuauRW_TValue.from_analysis(vaddr, self, safe_load=False)
            pot_tt[tvalue.tt].append(tvalue)
            if tvalue.tt in VALID_OBJ_TYPES and self.valid_vaddr(tvalue.value.gc):
                gco = self.read_gco(tvalue.value.gc)
                if gco is not None:
                    if a_lp is not None:
                        a_lp.add_obj(gco)
                        a_lp.add_tvalue(tvalue)
                    pot_gco[tvalue.value.gc] = gco
                    pot_tval[vaddr] = tvalue
                    if add_obj:
                        self.add_gc_object(vaddr, gco, ref_addr=None)
            vaddr += incr
        self.log.debug(
            "lua_Page {:08x} of size: {} found {} tvalues and {} gcos".format(lp.addr, lp.pageSize, len(pot_tval),
                                                                              len(pot_gco)))
        return results
