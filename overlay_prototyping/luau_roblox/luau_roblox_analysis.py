import ctypes
import json
import string
import threading
import time
from threading import Thread

from .consts import *
from .enumerate_luau_roblox import LuauSifterResults, LuauSifterResult, LuauByfronSifterResult
from .luau_roblox_page import LuaPages
# from .luau_roblox_base import LuauRobloxBase
from .overlay_base import LuauRW_BaseStruct, LuauRW_TString, LuauRW_lua_State, LuauRW_Udata, LuauRW_Table, \
    LuauRW_UpVal, LuauRW_Closure, LuauRW_GCHeader, LuauRW_TValue, LuauRW_global_State, \
    LuauRW_lua_Page, LuauRW_ProtoECB, GCO_TT_MAPPING, GCO_NAME_MAPPING
from .overlay_byfron import LuauRWB_TString, LuauRWB_lua_State, LuauRWB_Udata, LuauRWB_Table, \
    LuauRWB_UpVal, LuauRWB_Closure, LuauRWB_TValue, LuauRWB_global_State, \
    LuauRWB_ProtoECB, LuauRWB_GCHeader, LuauRWB_lua_Page, GCO_TT_BMAPPING, GCO_NAME_BMAPPING
from ..analysis import Analysis, MemRange
from ..base import BaseException


class LuauRobloxAnalysis(Analysis):
    def __init__(self, sift_results=None, luapage_pointers_file=None, byfron_analysis=False, save_state=None, **kargs):
        super(LuauRobloxAnalysis, self).__init__(name="LuauRobloxAnalysis", **kargs)
        self.luapage_pointers_file = luapage_pointers_file
        self.lrss = None
        self.strings = {}
        self.prims = {}
        self.load_srt = None
        self.analysis_thread = None
        self.analysis_results = None
        if not hasattr(self, 'is_32bit'):
            self.is_32bit = True

        self.sift_results = sift_results
        self.sift_results_loaded = False
        self.anchor_objects = {}
        self.anchor_sections = {}
        self._anchor_mr = {}
        self.objects_by_anchor_section = {}
        self.save_state_file = save_state
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
        self.lrss = LuauSifterResults(byfron_sift_results=byfron_analysis)
        self.GCO_TT_MAPPING = GCO_TT_MAPPING
        self.GCO_NAME_MAPPING = GCO_NAME_MAPPING
        self.GCHeaderCls = LuauRW_GCHeader
        self.TValueCls = LuauRW_TValue
        self.GlobalStateCls = LuauRW_global_State
        self.LuaPageCls = LuauRW_lua_Page
        self.byfron_analysis = byfron_analysis
        if byfron_analysis:
            self.GCO_TT_MAPPING = GCO_TT_BMAPPING
            self.GCO_NAME_MAPPING = GCO_NAME_BMAPPING
            self.GCHeaderCls = LuauRWB_GCHeader
            self.TValueCls = LuauRWB_TValue
            self.GlobalStateCls = LuauRWB_global_State
            self.LuaPageCls = LuauRWB_lua_Page

        self.state_association = {}
        self.free_blocks = {}

    def load_lua_pages(self, luapage_pointers_file=None):
        luapage_pointers_file = self.luapage_pointers_file if luapage_pointers_file is None else luapage_pointers_file
        if luapage_pointers_file is None:
            raise Exception("No pointer file provided")
        self.luapage_pointers_file = luapage_pointers_file
        lua_page_finds = [json.loads(i) for i in open(luapage_pointers_file).readlines()]
        pages = [self.LuaPageCls.from_analysis(int(lpj['vaddr'], 16), self) for lpj in lua_page_finds]
        pages = [i for i in pages if self.sanity_check_lua_page(i)]
        results = []
        already_visited = set(self.lua_pages.get_known_page_addrs())
        for i in pages:
            if i.addr in already_visited:
                continue
            r = self.walk_lua_pages(i)
            already_visited.add(i.addr)
            for l in r:
                already_visited.add(l.addr)
            results = r + results

        f = {i.addr: i for i in results}
        return list(f.values())

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

    def read_table_values(self, ttable: LuauRW_Table | LuauRWB_Table, add_obj=False) -> dict[LuauRW_TValue]:
        sizearray = ttable.sizearray
        tvalues = {}
        for idx in range(0, sizearray):
            tva = ttable.get_tvalue_address(idx)
            tvalue = self.TValueCls.from_analysis(tva, self)
            tvalues[tvalue.addr] = tvalue
            if add_obj:
                self.add_struct_object(tva, tvalue)
        return tvalues

    def get_lua_objs_by_memcat(self, memcat, tt=None) -> dict[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata |
        LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata]:
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
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata |
        LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata]:
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
                       tt=None) -> None | LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata | LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata:
        if tt is not None and vaddr in self.lua_gco[tt]:
            return self.lua_gco[tt][vaddr]
        for gcos in self.lua_gco.values():
            if vaddr in gcos:
                return gcos[vaddr]
        return None

    def get_strings(self) -> dict[LuauRW_TString | LuauRWB_TString]:
        return self.get_lua_objs(TSTRING)

    def walk_strings(self, add_obj=True):
        starting = self.get_strings()
        not_visited = [i.next for i in starting.values() if i.next != 0 and i.next not in starting]
        visited = set(starting.keys())
        new_strs = []
        while len(not_visited) > 0:
            vaddr = not_visited.pop()
            if vaddr in visited:
                continue
            gco = self.read_gco(vaddr, tt=TSTRING, add_obj=add_obj)
            if gco is not None:
                if gco.next > 0 and gco.next not in visited:
                    not_visited.append(gco.next)
                new_strs.append(gco)
        return new_strs

    def get_udatas(self) -> dict[LuauRW_Udata | LuauRWB_Udata]:
        return self.get_lua_objs(TUSERDATA)

    def get_closures(self) -> dict[LuauRW_Closure | LuauRWB_Closure]:
        return self.get_lua_objs(TCLOSURE)

    def get_tables(self) -> dict[LuauRW_Table | LuauRWB_Table]:
        return self.get_lua_objs(TTABLE)

    def get_protos(self) -> dict[LuauRW_ProtoECB | LuauRWB_ProtoECB]:
        return self.get_lua_objs(TPROTO)

    def get_upvals(self) -> dict[LuauRW_UpVal | LuauRWB_UpVal]:
        return self.get_lua_objs(TUPVAL)

    def get_threads(self) -> dict[LuauRW_lua_State | LuauRWB_lua_State]:
        return self.get_lua_objs(TTHREAD)

    def check_results_status(self) -> bool:
        if hasattr(self, 'sift_results_loaded') and self.sift_results_loaded:
            return True
        elif hasattr(self, 'load_srt') and self.load_srt and self.load_srt.is_alive():
            self.log.debug(
                "Still loading. loaded potential gcos from {} and potential structs {} results from {}".format(
                    len(self.lrss.gco_results), len(self.lrss.struct_results), self.sift_results))
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

    def scan_lua_pages_gco(self, add_obj=False, scan_entire_block=False) -> [
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata |
        LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata]:
        lpages = self.lua_pages.get_pages()
        objs = []
        checked = []
        self.valid_lua_gco_pages = []
        for lpage in lpages:
            # evaluate whether this lua_Page is relevant and should be searched
            if any([i[0] < lpage.addr < i[1] for i in checked]):
                self.log.debug("lua_Page already checked, lua_Page @ 0x{:08x} ".format(lpage.addr))
                continue
            # elif lpage.pageSize > 0x8000 or lpage.pageSize <= 0x100:
            #     self.log.debug(
            #         "lua_Page size is incompatible with scan ({}), lua_Page @ 0x{:08x} ".format(hex(lpage.pageSize),
            #                                                                                     lpage.addr))
            #     continue
            lpage_start = lpage.addr
            lpage_end = lpage.addr + 24 + lpage.pageSize
            checked.append([lpage_start, lpage_end])
            r = self.scan_lua_page_gco(lpage=lpage, add_obj=add_obj, scan_entire_block=scan_entire_block)
            if len(r) > 0:
                self.log.debug("Found {} new objects in lua_Page @ 0x{:08x} ".format(len(r), lpage.addr))
                objs = objs + r
                self.valid_lua_gco_pages.append(lpage)
            else:
                self.log.debug("No objects in lua_Page @ 0x{:08x} ".format(lpage.addr))

        self.valid_lua_gco_pages = sorted(self.valid_lua_gco_pages, key=lambda x: x.addr)
        return objs

    def scan_block_for_gco(self, block_addr, block_size, add_obj=False, printable_strings=True, incr=4,
                           tables=None, scan_entire_block=False, do_sanity_check=True) -> [
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata |
        LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata]:

        tables = tables if isinstance(tables, list) else []
        objs = []
        gco_addr = block_addr
        end_addr = block_addr + block_size
        while gco_addr < end_addr:
            if not self.has_gco(gco_addr):
                gco = self.read_gco(gco_addr, caution=False)
                if gco is None:
                    gco_addr += incr
                    continue

                r = []
                if gco is not None:
                    r = [gco]
                if gco is not None and do_sanity_check:
                    r = self.sanity_check(gco, add_obj=add_obj, printable_strings=printable_strings, tables=tables)
                if isinstance(r, list) and len(r) > 0:
                    # self.log.debug("Found new gco @ 0x{:08x} tt: {} ".format(gco_addr, gco.tt))
                    incr = gco.get_total_size()
                    objs.append(gco)
                    self.lua_pages.add_obj(gco)
                    if isinstance(gco, self.GCO_TT_MAPPING.get(TTABLE)):
                        tables.append(gco)
            else:
                # this GCO was already known, let's look it up and skip over the size
                gco = self.get_gco(gco_addr)
                self.log.debug("Found existing gco @ 0x{:08x} tt: {} ".format(gco_addr, gco.tt if gco else "INVALID"))
                incr = gco.get_total_size()
                objs.append(gco)
            if not scan_entire_block:
                break
            gco_addr += incr
        return objs

    def scan_lua_page_gco(self, addr=None, lpage=None, add_obj=False, printable_strings=True, incr=4, scan_entire_block=False, do_sanity_check=True) -> [
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata |
        LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata]:
        objs = []
        if addr is None and lpage is None:
            return objs
        elif addr is None and not (isinstance(lpage, LuauRW_lua_Page) or isinstance(lpage, LuauRWB_lua_Page)):
            return objs
        elif lpage is None and isinstance(addr, int):
            lpage_obj = self.lua_pages.get_page_with_addr(addr)
            if lpage_obj is None:
                return objs
            lpage = lpage_obj.lpage

        if lpage is None or lpage.pageSize <= 0:
            return objs

        tables = list(self.get_tables().values())
        self.log.debug("Scanning lua Page @ 0x{:08x} (sz={}) for GCOs".format(lpage.addr, lpage.pageSize))
        # TODO scan by block size
        block_size = lpage.blockSize
        if block_size <= 8:
            return objs

        data_start = lpage.get_offset('data') + lpage.addr
        data_end = lpage.addr + lpage.pageSize

        block_addrs = [i for i in range(data_start, data_end, block_size) if data_start <= i < data_end]
        self.log.debug(
            "Scanning {} ({} size) blocks in lua_Page {:08x} gcos".format(len(block_addrs), block_size, lpage.addr))
        if len(block_addrs) == 0:
            return objs

        for block_addr in block_addrs:
            # first 8 bytes of a block are metadata that point to the top of the page
            offset = 0
            value = self.read_ptr(block_addr, word_sz=self.word_sz)
            # FIXME why is this None
            # if value is None:
            #     continue
            if value is not None and self.valid_vaddr(value) and value == lpage.addr:
                self.free_blocks[block_addr] = lpage
                self.log.debug(
                    "Block {:08x} in lua_Page {:08x} has been freed".format(block_addr, lpage.addr))
                break
            _objs = self.scan_block_for_gco(block_addr + offset, block_size + offset, add_obj=add_obj,
                                            printable_strings=printable_strings, incr=incr, tables=tables,
                                            scan_entire_block=scan_entire_block, do_sanity_check=do_sanity_check)
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
                    len(self.lrss.gco_results), len(self.lrss.struct_results), self.sift_results))
        return self.sift_results_loaded

    def thread_completed(self):
        self.log.debug("Sift results loading Completed.")
        self.mark_complete(from_callback=True)
        self.log.debug("Starting the analysis thread")
        self.analysis_thread = threading.Thread(target=self.sift_results_load_complete)
        self.analysis_thread.start()

    def load_sift_results(self, pointer_file=None, background=True, bulk_load=True) -> bool:
        if self.sift_results is None and pointer_file is None:
            raise BaseException("No sift results file set")

        if self.load_srt is not None:
            return self.check_results_status()

        if self.sift_results is None:
            self.sift_results = pointer_file

        self.log.debug("Loading luau-sifter results from {}".format(self.sift_results))

        kwargs = {'bulk_load': bulk_load, 'callback': self.thread_completed}
        self.load_srt = Thread(target=self.lrss.parse_file, kwargs=kwargs, args=(self.sift_results,))
        self.load_srt.start()
        if not background:
            self.load_srt.join()
        return self.check_results_status()

    def get_gco_overlay(self, vaddr, ctypes_cls, buf=None, ref_addr=None, add_obj=False, sanity_check=False,
                        caution=False) -> None | LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata | LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata:
        ett = getattr(ctypes_cls, '_tt_', None)
        if ett is None or not ctypes_cls.has_gc_header() or vaddr in self.not_lua_objects[ett]:
            return None

        obj_sz = ctypes.sizeof(ctypes_cls)
        buf = self.read_vaddr(vaddr, obj_sz) if buf is None or len(buf) != obj_sz else buf
        if buf is None or len(buf) != obj_sz and not caution:
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

        if sanity_check and self.sanity_check(gco) and add_obj:
            self.add_gc_object(vaddr, gco, ref_addr=ref_addr)
        elif not sanity_check and add_obj:
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

    def add_string_at_vaddr(self, vaddr, ref_vaddr=None) -> None | LuauRW_TString | LuauRWB_TString:
        obj = self.get_lua_object(vaddr, TSTRING)
        if obj is not None and obj.is_string():
            return obj
        data = self.read_vaddr(vaddr, self.DEFAULT_OBJECT_READ_SZ)
        s = self.GCO_TT_MAPPING.get(TSTRING).from_bytes(vaddr, data, analysis=self, word_sz=self.word_sz)
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
                 caution=False) -> None | LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata | LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata:
        if tt is None:
            gco = None
            try:
                gco = self.GCHeaderCls.from_analysis(vaddr, self)
            except:
                if caution:
                    raise
            if gco is not None:
                tt = gco.tt
            # else:
            #     self.bad_obj_address(vaddr)

        if tt not in self.GCO_TT_MAPPING:
            return None
        elif vaddr in self.not_lua_objects[tt]:
            return None

        cls = self.GCO_TT_MAPPING.get(tt)
        return self.get_gco_overlay(vaddr, cls, add_obj=add_obj, caution=caution)

    def read_tvalue(self, vaddr, index=0, add_obj=False, caution=False) -> None | LuauRW_TValue | LuauRWB_TValue:
        tv = self.TValueCls.from_analysis(vaddr, self)
        return tv

    def read_gco_ptr(self, pvaddr, tt=None, word_sz=4, little_endian=True, add_obj=False,
                     caution=False) -> None | LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata | LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata:
        vaddr = None
        if tt is None:
            vaddr = self.deref_address(pvaddr, word_sz, little_endian)
            if vaddr is None:
                self.bad_obj_address(pvaddr)
                return None
            gco = self.GCHeaderCls.from_analysis(vaddr, self)
            if gco is not None:
                tt = gco.tt
            else:
                self.bad_obj_address(vaddr)

        if vaddr is None:
            return None
        elif tt not in self.GCO_TT_MAPPING:
            return None
        elif vaddr in self.not_lua_objects[tt]:
            return None

        cls = self.GCO_TT_MAPPING.get(tt)
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

    def find_lua_strings_from_sift_file(self) -> dict[LuauRW_TString | LuauRWB_TString]:
        if not self.memory_loaded:
            self.load_memory()

        if not self.sift_results_loaded:
            self.load_sift_results()

        return self.get_strings_from_sifter_results()

    def get_potential_objects_from_sifter(self, tt, perform_overlay=True, add_obj=False) -> list[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata |
        LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata]:
        results = []
        for o in self.lrss.get_potential_objects():
            # this is a sifter result and not an object
            if o.is_valid_gc_header() and o.tt == tt:
                if perform_overlay:
                    cls_type = self.GCO_TT_MAPPING.get(tt)
                    obj = self.get_gco_overlay(o.sink_vaddr, cls_type, add_obj=add_obj)
                    if obj is not None:
                        results.append(obj)
                else:
                    results.append(o)
        return results

    def sanity_check(self, obj, add_obj=False, printable_strings=False, tables=None) -> None | list[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata |
        LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata]:
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

    def sanity_check_tstrings(self, tstring_list, add_obj=False, printable_strings=False) -> list[
        LuauRW_TString | LuauRWB_TString]:
        tstrings = []
        for obj in tstring_list:
            if not self.check_string(obj, printable_string=False):
                continue

            tstrings.append(obj)
            self.strings[obj.addr] = obj
            value = None if not isinstance(obj, self.GCO_TT_MAPPING.get(TSTRING)) else obj.get_value()
            if printable_strings and value is not None and self.is_printable_string(value):
                self.printable_strings[obj.addr] = obj

        if add_obj:
            for o in tstrings:
                self.add_gc_object(o.addr, o)

        if printable_strings:
            tstrings = list(self.printable_strings.values())
        return tstrings

    def potentials_tstrings(self, sanity_check=False, add_obj=False, printable_strings=True, tables=None) -> list[
        LuauRW_TString | LuauRWB_TString]:
        r = self.get_potential_objects_from_sifter(TSTRING)
        if sanity_check:
            return self.sanity_check_tstrings(r, add_obj=add_obj, printable_strings=printable_strings)
        return r

    def sanity_check_closures(self, closeure_list, add_obj=False, tables=None) -> list[
        LuauRW_Closure | LuauRWB_Closure]:
        if tables is None:
            tables = self.potentials_tables(sanity_check=True, add_obj=add_obj)
        dt = {t.addr: t for t in tables}
        closures = []
        for obj in closeure_list:
            if obj.env in dt:
                closures.append(obj)
                continue
            elif not self.valid_vaddr(obj.env):
                continue
            gco = self.read_gco(obj.env, tt=TTABLE, add_obj=True, caution=False)
            if gco is None:
                continue
            dt[gco.addr] = gco
        if add_obj:
            for o in closures:
                self.add_gc_object(o.addr, o)
        return closures

    def potentials_closures(self, sanity_check=False, add_obj=False, tables=None) -> list[
        LuauRW_Closure | LuauRWB_Closure]:
        r = self.get_potential_objects_from_sifter(TCLOSURE)
        if sanity_check:
            self.sanity_check_closures(r, add_obj=add_obj, tables=tables)
        return r

    def sanity_check_userdatas(self, userdata_list, add_obj=False, tables=None) -> list[LuauRW_Udata | LuauRWB_Udata]:
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

    def potentials_userdatas(self, sanity_check=False, add_obj=False, tables=None) -> list[
        LuauRW_Udata | LuauRWB_Udata]:
        r = self.get_potential_objects_from_sifter(TUSERDATA)
        if sanity_check:
            return self.sanity_check_userdatas(r, add_obj=add_obj, tables=tables)
        return r

    def sanity_check_threads(self, thread_list, add_obj=False, tables=None) -> list[LuauRWB_lua_State]:
        threads = []
        dt = {t.addr: t for t in thread_list}
        if tables is None:
            tables = self.potentials_tables(sanity_check=True, add_obj=add_obj)
        dtables = {t.addr: t for t in tables}
        for obj in dt.values():
            # handle gt if its NULL, we just accept it, otherwise try to associate with a Lua Table
            gt_valid = obj.gt == 0
            if not gt_valid and self.valid_vaddr(obj.gt):
                gco = self.get_gco(obj.gt)
                gt_valid = isinstance(gco, LuauRWB_Table) or isinstance(gco, LuauRW_Table)
                if not gt_valid and self.valid_vaddr(obj.gt):
                    gco = self.read_gco(obj.gt, tt=TTABLE, add_obj=True, caution=False)
                    gt_valid = gco is not None

            global_state = getattr(obj, 'global_State') == 0 or self.valid_vaddr(getattr(obj, 'global_State'))
            call_info = obj.ci == 0 or self.valid_vaddr(obj.ci)
            stack = obj.stack == 0 or self.valid_vaddr(obj.stack)
            stack_last = obj.stack_last == 0 or self.valid_vaddr(obj.stack_last)
            # relaxing the check on the global table.  may not be known

            # all_checks = [global_state, call_info, stack, stack_last, gt_valid]
            all_checks = [ global_state, gt_valid]
            if all(all_checks):
                threads.append(obj)
        if add_obj:
            for o in threads:
                self.add_gc_object(o.addr, o)
        return threads

    def potentials_threads(self, sanity_check=False, add_obj=False, tables=None) -> list[
        LuauRW_lua_State | LuauRWB_lua_State]:
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

    def potentials_tables(self, sanity_check=False, add_obj=False) -> list[LuauRW_Table | LuauRWB_Table]:
        r = self.get_potential_objects_from_sifter(TTABLE)
        if sanity_check:
            return self.sanity_check_tables(r, add_obj=add_obj)
        return r

    def sanity_check_protos(self, protos_list, add_obj=False, check_execdata=True, tables=None) -> list[
        LuauRW_ProtoECB | LuauRWB_ProtoECB]:
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
                if isinstance(p, self.GCO_TT_MAPPING.get(TPROTO)) else True
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
        LuauRW_ProtoECB | LuauRWB_ProtoECB]:
        r = self.get_potential_objects_from_sifter(TPROTO)
        if sanity_check:
            return self.sanity_check_protos(r, add_obj=add_obj, check_execdata=check_execdata, tables=tables)
        return r

    def sanity_check_upvals(self, upvals_list, add_obj=False) -> list[LuauRW_UpVal | LuauRWB_UpVal]:
        upvals = []
        for obj in upvals_list:
            gco_valid = False
            if self.valid_vaddr(obj.v):
                tvalue = None
                try:
                    tvalue = self.TValueCls.from_analysis(obj.v, self)
                    if tvalue.tt in self.GCO_TT_MAPPING and self.valid_vaddr(tvalue.value.gc):
                        gco = self.read_gco(tvalue.value.gc, tt=tvalue.tt, caution=False)
                        if gco is not None:
                            self.add_gc_object(gco.addr, gco, ref_addr=tvalue.addr)
                            gco_valid = True
                    else:
                        continue
                except:
                    continue

                # its an object
                if tvalue and tvalue.tt in self.GCO_TT_MAPPING and self.valid_vaddr(tvalue.value.gc):
                    upvals.append(obj)
                # its a value not an object
                elif tvalue and tvalue.tt in LUA_TAG_TYPES and tvalue.tt not in GCO_TT_BMAPPING:
                    upvals.append(obj)
        if add_obj:
            for o in upvals:
                self.add_gc_object(o.addr, o)
        return upvals

    def potentials_upvals(self, sanity_check=False, add_obj=False, tables=None) -> list[LuauRW_UpVal | LuauRWB_UpVal]:
        r = self.get_potential_objects_from_sifter(TUPVAL)
        if sanity_check:
            return self.sanity_check_upvals(r, add_obj=add_obj)
        return r

    def find_potential_global_state(self, pot_threads=None) -> dict[LuauRW_global_State | LuauRWB_global_State]:
        globals_results = {}
        pot_threads = self.potentials_threads() if pot_threads is None else pot_threads
        gs_addrs = {getattr(i, 'global_State'): i for i in pot_threads if
                    i is not None and self.valid_vaddr(getattr(i, 'global_State'))}

        global_states = [self.GlobalStateCls.from_analysis(i, self, safe_load=False) for i in gs_addrs]
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

    def get_memrange(self, vaddr) -> MemRange:
        return self.mem_ranges.get_memrange_from_vaddr(vaddr)

    def get_objects_in_section(self, vaddr) -> list[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata | LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata]:
        results = []
        mr = self.get_memrange(vaddr)
        if mr is None:
            return results

        for v in self.get_pot_objects_in_section(vaddr):
            addr = v.sink_vaddr
            if mr.vaddr_in_range(addr):
                results.append(v)
        return results

    def get_pot_objects_in_section(self, vaddr) -> list[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata | LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata]:
        results = []
        mr = self.get_memrange(vaddr)
        if mr is None:
            return results
        pot_objects = self.lrss.get_potential_objects()
        for v in pot_objects:
            if not v.is_valid_gc_header():
                continue
            addr = v.sink_vaddr
            if mr.vaddr_in_range(addr):
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
            if mr.vaddr_in_range(addr):
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
            if mr.vaddr_in_range(addr):
                results.append(v)
        return results

    def get_strings_from_sifter_results(self) -> dict[LuauRW_TString | LuauRWB_TString]:
        pot_tstrings = self.lrss.get_potential_tstrings()
        for ts in pot_tstrings:
            vaddr = ts.sink_vaddr
            if vaddr in self.strings:
                continue
            ref_vaddr = ts.vaddr
            self.add_string_at_vaddr(vaddr, ref_vaddr=ref_vaddr)
        return self.get_strings()

    def get_builtin_strings_from_sifter_results(self) -> dict[LuauRW_TString | LuauRWB_TString]:
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

    def find_anchor_strings(self) -> dict[LuauRW_TString | LuauRWB_TString]:
        if not self.is_sift_results_loaded():
            self.load_sift_results()
        lua_strings = self.get_safe_strings()

        anchor_objects = {}
        for s in lua_strings.values():
            value = None if not isinstance(s, self.GCO_TT_MAPPING.get(TSTRING)) else s.get_value()
            if len(str(value)) == 0:
                continue
            if value in LUAR_ROBLOX_TYPES or value in LUAR_ROBLOX_EVENT_NAMES:
                anchor_objects[s.addr] = s

        self.anchor_objects.update(anchor_objects)
        return anchor_objects

    def find_anchor_objects(self) -> dict[
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata | LuauRWB_Table | LuauRWB_ProtoECB | LuauRWB_TString | LuauRWB_Closure | LuauRWB_UpVal | LuauRWB_lua_State | LuauRWB_Udata]:
        self.anchor_objects = {}
        if not self.is_sift_results_loaded():
            self.load_sift_results()

        # lua_strings
        self.find_anchor_strings()
        self.find_anchor_pages()

        # now that we have anchor pages
        # find all gco threads
        return self.anchor_objects

    def get_printable_strings(self):
        strings = self.get_strings()
        for addr, tstring in strings.items():
            if tstring is None or tstring.get_value() is None:
                continue
            if addr not in self.printable_strings and self.is_printable_string(tstring.get_value()):
                self.printable_strings[addr] = tstring
        return self.printable_strings

    def is_printable_string(self, value) -> bool:
        return value is not None and all([i in string.printable for i in value])

    def get_safe_strings(self, rerun=True) -> dict[LuauRW_TString | LuauRWB_TString]:
        if not rerun:
            return self.printable_strings
        lua_strings = self.potentials_tstrings(sanity_check=True, printable_strings=True, add_obj=True)
        return {o.addr: o for o in lua_strings}

    def find_printable_strings(self) -> list[LuauRW_TString]:
        pstrings = []
        tstrings = self.potentials_tstrings(sanity_check=True, printable_strings=True)
        for obj in tstrings:
            value = None if not (isinstance(obj, self.GCO_TT_MAPPING.get(TSTRING))) else obj.get_value()
            if all([i in string.printable for i in value]):
                pstrings.append(obj)
        return pstrings

    def check_string(self, obj, printable_string=False) -> bool:
        if printable_string and obj.addr in self.printable_strings:
            return True
        elif not printable_string and obj.addr in self.strings:
            return True

        if not self.valid_vaddr(obj.end) or obj.end < obj.addr:
            return False
        value = None if not (isinstance(obj, self.GCO_TT_MAPPING.get(TSTRING))) else obj.get_value()
        if value is None or len(value) > MAXSSIZE:
            return False
        elif printable_string and not self.is_printable_string(value):
            return False
        return True

    def enumerate_objects_in_anchor_sections(self):
        lua_strings = self.get_strings_from_sifter_results()
        for base_vaddr, as_json in self.anchor_sections.items():
            mr = as_json['memory_range']
            self.objects_by_anchor_section[base_vaddr] = {'object_vaddrs': {}, 'memory_range': mr}
            addrs = [k for k in self.get_gco_addresses() if mr.vaddr_in_range(k)]
            self.objects_by_anchor_section[base_vaddr]['object_vaddrs'] = set(addrs)
            self.objects_by_anchor_section[base_vaddr]['objects'] = {a: self.get_gco(a) for a in addrs}
            self.objects_by_anchor_section[base_vaddr]['strings'] = {a: self.get_gco(a) for a in addrs}
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
                analysis.log.error("Failed at 0x{:08x}, advancing to 0x{:08x}".format(next_addr, _next_addr))
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
                self.log.error("Failed at 0x{:08x}, advancing to 0x{:08x}".format(next_addr, _next_addr))
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

    def find_lua_pages(self, max_size=DEFAULT_MAX_SIZE) -> list[LuauRW_lua_Page]:
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
            _ = self.walk_lua_pages(lpage, max_size=max_size)
        return list(self.lua_pages.get_pages())

    def sanity_check_lua_page(self, lpage: LuauRW_lua_Page | LuauRWB_lua_Page, max_size=DEFAULT_MAX_SIZE):
        if not isinstance(lpage, self.LuaPageCls):
            self.log.debug(
                "lua_Page failed sanity check 0x{:08x}: invalid python class".format(lpage.addr))
            return False
        elif lpage.pageSize > max_size or lpage.pageSize < 32:
            self.log.debug(
                "lua_Page failed sanity check 0x{:08x}: lpage.pageSize > max_size or lpage.pageSize < 32".format(
                    lpage.addr))
            return False
        elif lpage.blockSize <= 7:# or lpage.blockSize > max_size:
            self.log.debug(
                "lua_Page failed sanity check 0x{:08x}: lpage.blockSize <= 7 or lpage.blockSize > max_size".format(
                    lpage.addr))
            return False
        elif lpage.pageSize < lpage.blockSize:
            self.log.debug(
                "lua_Page failed sanity check 0x{:08x}: lpage.pageSize < lpage.blockSize".format(lpage.addr))
            return False
        elif lpage.pageSize < lpage.blockSize * lpage.busyBlocks:
            self.log.debug(
                "lua_Page failed sanity check 0x{:08x}: lpage.pageSize < lpage.blockSize * lpage.busyBlocks".format(
                    lpage.addr))
            return False
        return True

    def walk_lua_page_gcolist_forward(self, lua_page, max_size=DEFAULT_MAX_SIZE) -> list[LuauRW_lua_Page]:
        # walk GCO List forward
        lua_pages = []
        self.log.debug(
            "Walking the lua_Page linked lists forward from at 0x{:08x}".format(lua_page.gcolistnext))
        nlp = lua_page
        while True:
            if nlp is None or nlp.gcolistnext == 0 or \
                    not self.valid_vaddr(nlp.gcolistnext):
                break
            nlp = self.LuaPageCls.from_analysis(nlp.gcolistnext, analysis=self, safe_load=False)
            if self.lua_pages.has_page(nlp) or not self.sanity_check_lua_page(nlp, max_size=max_size):
                break
            if nlp is not None and self.sanity_check_lua_page(nlp, max_size=max_size):
                self.lua_pages.add_page(nlp)
                lua_pages.append(nlp)
        return lua_pages

    def walk_lua_page_freelist_forward(self, lua_page, max_size=DEFAULT_MAX_SIZE) -> list[LuauRW_lua_Page]:
        # walk GCO List forward
        lua_pages = []
        self.log.debug(
            "Walking the lua_Page linked lists forward from at 0x{:08x}".format(lua_page.next))
        nlp = lua_page
        while True:
            if nlp is None or nlp.next == 0 or \
                    not self.valid_vaddr(nlp.next):
                break
            nlp = self.LuaPageCls.from_analysis(nlp.next, analysis=self, safe_load=False)
            if self.lua_pages.has_page(nlp) or not self.sanity_check_lua_page(nlp, max_size=max_size):
                break
            if nlp is not None and self.sanity_check_lua_page(nlp, max_size=max_size):
                self.lua_pages.add_page(nlp)
                lua_pages.append(nlp)
        return lua_pages

    def walk_lua_page_freelist_backward(self, lua_page, max_size=DEFAULT_MAX_SIZE) -> list[LuauRW_lua_Page]:
        # walk GCO List forward
        lua_pages = []
        self.log.debug(
            "Walking the lua_Page linked lists forward from at 0x{:08x}".format(lua_page.prev))
        nlp = lua_page
        while True:
            if nlp is None or nlp.prev == 0 or \
                    not self.valid_vaddr(nlp.prev):
                break
            nlp = self.LuaPageCls.from_analysis(nlp.prev, analysis=self, safe_load=False)
            if self.lua_pages.has_page(nlp) or not self.sanity_check_lua_page(nlp, max_size=max_size):
                break
            if nlp is not None and self.sanity_check_lua_page(nlp, max_size=max_size):
                self.lua_pages.add_page(nlp)
                lua_pages.append(nlp)
        return lua_pages

    def walk_lua_page_gcolist_backward(self, lua_page, max_size=DEFAULT_MAX_SIZE) -> list[LuauRW_lua_Page]:
        lua_pages = []
        # walk GCO List backward
        self.log.debug(
            "Walking the lua_Page linked lists backward from at 0x{:08x}".format(lua_page.gcolistprev))
        nlp = lua_page
        while True:
            if nlp is None or nlp.gcolistprev == 0 or \
                    not self.valid_vaddr(nlp.gcolistprev):
                break
            nlp = self.LuaPageCls.from_analysis(nlp.gcolistprev, analysis=self, safe_load=False)
            if self.lua_pages.has_page(nlp) or not self.sanity_check_lua_page(nlp, max_size=max_size):
                break
            if nlp is not None and self.sanity_check_lua_page(nlp, max_size=max_size):
                self.lua_pages.add_page(nlp)
                lua_pages.append(nlp)
        return lua_pages

    def walk_lua_pages(self, lua_page, max_size=DEFAULT_MAX_SIZE) -> list[LuauRW_lua_Page]:
        '''
        walk the lua pages to find the allocations
        :param lua_page:
        :return:
        '''
        already_visited = set(self.lua_pages.get_known_page_addrs())
        visited = set()
        if lua_page.addr in already_visited or not self.sanity_check_lua_page(lua_page):
            return []

        if lua_page is not None and self.sanity_check_lua_page(lua_page, max_size=max_size):
            flua_pages = self.walk_lua_page_gcolist_forward(lua_page, max_size=max_size)
            blua_pages = self.walk_lua_page_gcolist_backward(lua_page, max_size=max_size)

            # enumerate any new pages froom the ones that were found
            self.log.debug("Reviewing results and looking for undiscovered links in lists")
            not_visited_pages = set()
            self.lua_pages.add_page(lua_page)
            for nlp in flua_pages + blua_pages:
                if not self.sanity_check_lua_page(nlp, max_size=max_size):
                    visited.add(nlp.addr)
                    continue
                if nlp.gcolistprev > 0 and nlp.gcolistprev not in already_visited:
                    not_visited_pages.add(nlp.gcolistprev)
                if nlp.gcolistnext > 0 and nlp.gcolistnext not in already_visited:
                    not_visited_pages.add(nlp.gcolistprev)
                if nlp.next > 0 and nlp.next not in already_visited:
                    not_visited_pages.add(nlp.next)
                if nlp.prev > 0 and nlp.prev not in already_visited:
                    not_visited_pages.add(nlp.prev)


            already_visited = already_visited | visited
            not_visited_pages = list(not_visited_pages)
            self.log.debug("found {} unvisited lua pages".format(len(not_visited_pages)))
            # performing page discovery on the new pages
            while len(not_visited_pages) > 0:
                nla = not_visited_pages.pop()
                if nla in already_visited or nla in visited:
                    continue
                visited.add(nla)
                if nla == 0 or self.lua_pages.has_page_addr(nla) or not self.valid_vaddr(nla):
                    continue
                nlp = self.LuaPageCls.from_analysis(nla, analysis=self, safe_load=False)
                if not self.sanity_check_lua_page(nlp, max_size=max_size):
                    continue
                more_pages = self.walk_lua_pages(nlp)
                mp = [i.addr for i in more_pages if i.addr not in already_visited]
                visited = visited | set(mp)
        return [i for i in self.lua_pages.get_pages() if i.addr in visited]

    def find_lua_page_header(self, start_addr=None, allowed_failures=3, stop_addr=None,
                             block_size=32, max_size=DEFAULT_MAX_SIZE) -> LuauRW_lua_Page:
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
        pot_page_addr = pot_page_addr - ctypes.sizeof(self.LuaPageCls)
        pot_page_addr = pot_page_addr if pot_page_addr % 8 == 0 else pot_page_addr - (pot_page_addr % 8)

        self.log.debug(
            "Searching for the Luau lua_Page header between 0x{:08x} and 0x{:08x}".format(pot_page_addr, end_addr))

        while pot_page_addr < end_addr:
            lua_page = self.LuaPageCls.from_analysis(pot_page_addr, analysis=self, safe_load=False)
            if self.sanity_check_lua_page(lua_page) and lua_page.pageSize == 0x3fe8 and lua_page.blockSize == 32:
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

    def scan_lua_pages_tvalue(self, add_obj=False, num_threads=None, pot_gco=None, pot_tval=None, pot_tt=None):
        lua_pages = self.lua_pages.get_pages()
        pot_gco = {} if pot_gco is None else pot_gco
        pot_tval = {} if pot_tval is None else pot_tval
        pot_tt = {k: [] for k in LUA_TAG_TYPES} if pot_tt is None else pot_tt
        results = {'pot_gco': pot_gco, "pot_tval": pot_tval, 'pot_tt': pot_tt}
        num_lps = len(lua_pages)
        cnt = 0
        if isinstance(num_threads, int):
            active_threads = []
            while len(lua_pages) > 0:
                lp = lua_pages.pop(0)
                cnt += 1
                self.log.debug("Processing {} of {} lua_Pages ".format(cnt, num_lps))
                t = Thread(target=self.scan_lua_page_tvalue,
                           args=(lp,),
                           kwargs={'pot_gco': pot_gco, 'pot_tval': pot_tval, 'pot_tt': pot_tt, 'add_obj': add_obj})
                t.start()
                active_threads.append(t)
                active_threads = [i for i in active_threads if i.is_alive()]
                while len(active_threads) > num_threads:
                    time.sleep(1.0)
                    active_threads = [i for i in active_threads if i.is_alive()]

            while len(active_threads) > 0:
                time.sleep(1.0)
                active_threads = [i for i in active_threads if i.is_alive()]

            # try:
            #     futures = []
            #     with ProcessPoolExecutor(max_workers=num_threads) as executor:
            #         # iterate over lua pages and execute tvalue scan
            #         for lp in lua_pages:
            #             f = executor.submit(self.find_tvalues_in_lua_page, args=(lp,))
            #             futures.append(f)
            #
            #         # iterate over lua pages and execute tvalue scan
            #         for x in futures:
            #             pot_gco.update(x['pot_gco'])
            #             pot_tval.update(x['pot_tval'])
            #             for tt in x['pot_tt'].keys():
            #                 if tt not in pot_tt:
            #                     pot_tt[tt] = []
            #                 pot_tt[tt] = pot_tt[tt] + x['pot_tt'][tt]
            # except:
            #    raise
        if True:
            for lp in lua_pages:
                self.log.debug(
                    "Scanning lua_Page {:08x} of size: {} for tvalues".format(lp.addr, lp.pageSize))
                x = self.scan_lua_page_tvalue(lp, add_obj=add_obj)
                self.log.debug(
                    "lua_Page {:08x} found {} GCOs and found {} tvalues".format(lp.addr, len(x['pot_gco']), len(x['pot_tval'])))
                pot_gco.update(x['pot_gco'])
                pot_tval.update(x['pot_tval'])
                for tt in x['pot_tt'].keys():
                    if tt not in pot_tt:
                        pot_tt[tt] = []
                    pot_tt[tt] = pot_tt[tt] + x['pot_tt'][tt]
        return results

    def scan_block_for_tvalue(self, block_addr, block_size, add_obj=False, printable_strings=True, incr=4, tables=None,
                              pot_gco=None, pot_tt=None, pot_tval=None, parse_bare_pointers=False, do_sanity_check=True) -> [
        LuauRW_Table | LuauRW_ProtoECB | LuauRW_TString | LuauRW_Closure | LuauRW_UpVal | LuauRW_lua_State | LuauRW_Udata]:

        # tables = tables if isinstance(tables, list) else []
        pot_gco = {} if pot_gco is None else pot_gco
        pot_tval = {} if pot_tval is None else pot_tval
        pot_tt = {k: [] for k in LUA_TAG_TYPES} if pot_tt is None else pot_tt
        results = {'pot_gco': pot_gco, "pot_tval": pot_tval, 'pot_tt': pot_tt}

        a_lp = self.lua_pages.get_page_abstraction_with_addr(block_addr)
        lp = None if a_lp is None else a_lp.lpage
        # objs = []
        tval_addr = block_addr
        end_addr = block_addr + block_size
        incr = ctypes.sizeof(self.TValueCls)
        while tval_addr < end_addr:
            tval_tt = self.read_uint(tval_addr + 8)
            gc_addr = self.read_uint(tval_addr)
            if (tval_tt in VALID_OBJ_TYPES and self.valid_vaddr(gc_addr)) or \
                    (parse_bare_pointers and self.valid_vaddr(gc_addr)):
                tvalue = self.TValueCls.from_analysis(tval_addr, self, safe_load=False)
                gco = None
                if tvalue is not None:
                    gco = self.read_gco(tvalue.value.gc)

                r = []
                if gco is not None:
                    r = [gco]
                if gco is not None and do_sanity_check:
                    r = self.sanity_check(gco, add_obj=add_obj, printable_strings=printable_strings, tables=tables)
                if isinstance(r, list) and len(r) > 0:
                    incr = ctypes.sizeof(self.TValueCls)
                    if a_lp is not None:
                        a_lp.add_obj(gco)
                    pot_gco[tvalue.value.gc] = gco
                    pot_tval[tval_addr] = tvalue
                    if add_obj:
                        self.add_gc_object(tval_addr, gco, ref_addr=None)
            tval_addr += incr
        self.log.debug(
            "lua_Page {:08x} of size: {} @block {:08x} found {} tvalues and {} gcos".format(lp.addr if lp else block_addr,
                                                                                            lp.pageSize if lp else block_size,
                                                                                            block_addr,
                                                                                            len(pot_tval),
                                                                                            len(pot_gco)))
        return results

    def scan_lua_page_tvalue(self, lp: LuauRW_lua_Page | LuauRWB_lua_Page, add_obj=False, pot_gco=None, pot_tval=None, pot_tt=None):
        pot_gco = {} if pot_gco is None else pot_gco
        pot_tval = {} if pot_tval is None else pot_tval
        pot_tt = {k: [] for k in LUA_TAG_TYPES} if pot_tt is None else pot_tt
        results = {'pot_gco': pot_gco, "pot_tval": pot_tval, 'pot_tt': pot_tt}
        a_lp = self.lua_pages.get_page_abstraction_with_addr(lp.addr)

        if lp is None or lp.pageSize <= ctypes.sizeof(LuauRW_lua_Page):
            return results

        if a_lp is None:
            self.log.debug("Unable to associate the gcos and tvalues with with a lua_Page ".format())

        block_size = lp.blockSize
        data_start = lp.get_offset('data') + lp.addr
        block_addr = data_start + lp.pageSize - block_size
        if block_addr < data_start or block_addr <= 0:
            return results

        data_end = lp.addr + lp.pageSize
        data_start = lp.addr + lp.get_offset('data')
        if block_size <= 8:
            return results

        block_addrs = [i for i in range(data_start, data_end, block_size) if data_start <= i < data_end]
        self.log.debug(
            "Scanning {} ({} size) blocks in lua_Page {:08x} tvalues".format(len(block_addrs), block_size, lp.addr))
        for block_addr in block_addrs:
            # first 8 bytes of a block are metadata that point to the top of the page
            # if not self.valid_vaddr(block_addr):
            #     self.log.debug(
            #         "Block address 0x{:08x} in lua_Page: 0x{:08x} is invalid".format(block_addr, lp.addr))
            #     continue
            offset = 0
            value = self.read_ptr(block_addr, word_sz=self.word_sz)
            if value is not None and self.valid_vaddr(value) and value == lp.addr:
                self.free_blocks[block_addr] = lp
                offset = -8
            _ = self.scan_block_for_tvalue(block_addr + offset, block_size + offset, add_obj=add_obj, pot_gco=pot_gco,
                                           pot_tt=pot_tt,
                                           pot_tval=pot_tval)
        return results

    def get_state(self):
        results = []
        # capture the source informations
        meta_data = {}
        meta_data['sift_results'] = self.sift_results
        meta_data['luapage_pointers_file'] = self.luapage_pointers_file
        meta_data['byfron_analysis'] = self.byfron_analysis
        meta_data['save_state_file'] = self.save_state_file
        meta_data['dmp_file'] = self.dmp_file
        meta_data['radare_file'] = self.radare_file
        results.append(meta_data)
        addrs = set()

        # add discovered lps and gcos
        for lua_page in self.lua_pages.get_pages():
            lp_addr = lua_page.addr
            t = {'type': "LuauRW_lua_Page", "addr": lp_addr}
            addrs.add(lp_addr)
            _luapage = self.lua_pages.lpages[lp_addr]
            _gcos = [{'type': "{}".format(gco.__class__.__name__), 'addr': gco.addr, 'printable_string': gco.addr in self.printable_strings} for gco in
                     _luapage.objects.values() if gco]
            gcos = [i for i in _gcos if i['addr'] not in addrs]
            addrs |= {i['addr'] for i in gcos}
            # _gcos = [{'type':"{}".format(gco.__class__.__name__), 'addr':gco.addr } for gco in _luapage.tvalues.values() if gco]
            # gcos = [i for i in _gcos if i['addr'] not in addrs]
            # addrs |= {i['addr'] for i in gcos}

            results = results + [t] + gcos
        # add discovered gcos
        for tt in self.lua_gco:
            _gcos = [{'type': "{}".format(gco.__class__.__name__), 'addr': gco.addr, 'printable_string': gco.addr in self.printable_strings} for gco in
                     self.lua_gco[tt].values() if gco]
            gcos = [i for i in _gcos if i['addr'] not in addrs]
            addrs |= {i['addr'] for i in gcos}
            results = results + gcos

        # add other lua structures
        references = self.object_references.get_objects_and_references()
        for addr in references:
            gco = references[addr]['object']
            refs = references[addr]['references']
            gco_i = {'type': "{}".format(gco.__class__.__name__), 'addr': gco.addr, 'printable_string': gco.addr in self.printable_strings, 'references': sorted(refs)}
            addrs.add(addr)
            results = results + [gco_i]

        references = self.struct_references.get_objects_and_references()
        for addr in references:
            gco = references[addr]['object']
            refs = references[addr]['references']
            gco_i = {'type': "{}".format(gco.__class__.__name__), 'addr': gco.addr, 'printable_string': gco.addr in self.printable_strings, 'references': sorted(refs)}
            addrs.add(addr)
            results = results + [gco_i]

        return results

    def get_state_with_values(self):
        results = []
        addrs = set()

        # add discovered lps and gcos
        for lua_page in self.lua_pages.get_pages():
            lp_addr = lua_page.addr
            t = {'type': "LuauRW_lua_Page", "addr": lp_addr}
            addrs.add(lp_addr)
            _luapage = self.lua_pages.lpages[lp_addr]
            _gcos = [{'type': "{}".format(gco.__class__.__name__), 'addr': gco.addr, 'value': gco.get_value()} for gco
                     in _luapage.objects.values() if gco]
            gcos = [i for i in _gcos if i['addr'] not in addrs]
            addrs |= {i['addr'] for i in gcos}
            # _gcos = [{'type':"{}".format(gco.__class__.__name__), 'addr':gco.addr } for gco in _luapage.tvalues.values() if gco]
            # gcos = [i for i in _gcos if i['addr'] not in addrs]
            # addrs |= {i['addr'] for i in gcos}

            results = results + [t] + gcos
        # add discovered gcos
        for tt in self.lua_gco:
            _gcos = [{'type': "{}".format(gco.__class__.__name__), 'addr': gco.addr, 'value': gco.get_value()} for gco
                     in self.lua_gco[tt].values() if gco]
            gcos = [i for i in _gcos if i['addr'] not in addrs]
            addrs |= {i['addr'] for i in gcos}
            results = results + gcos

        # add other lua structures
        references = self.object_references.get_objects_and_references()
        for addr in references:
            gco = references[addr]['object']
            refs = references[addr]['references']
            gco_i = {'type': "{}".format(gco.__class__.__name__), 'addr': gco.addr, 'references': sorted(refs)}
            addrs.add(addr)
            results = results + [gco_i]

        references = self.struct_references.get_objects_and_references()
        for addr in references:
            gco = references[addr]['object']
            refs = references[addr]['references']
            gco_i = {'type': "{}".format(gco.__class__.__name__), 'addr': gco.addr, 'references': sorted(refs)}
            addrs.add(addr)
            results = results + [gco_i]

        return results

    def save_state(self, outputfile=None):
        outputfile = outputfile if isinstance(outputfile, str) else self.save_state_file
        if self.save_state_file is None:
            self.save_state_file = outputfile
        if outputfile is None:
            raise Exception("Unable to save state.  no output file specified")
        self.log.debug("Obtaining all relevant objects, structures, and references")
        results = self.get_state()
        fmt = "{}\n"
        self.log.debug("Writing state to {}".format(outputfile))
        with open(outputfile, 'w') as outfile:
            for line in results:
                outfile.write(fmt.format(json.dumps(line)))
        self.log.debug("Completed writing state to {}".format(outputfile))
        return results

    def restore_state(self, inputfile):
        hold_references = []
        added_addrs = set()
        tvals = []
        gcos = {}
        with open(inputfile, 'r') as infile:
            lines = [i.strip() for i in infile.readlines()]
            for line in lines:
                d = json.loads(line)
                if 'dmp_file' in line:
                    self.sift_results = line.get('sift_results', None)
                    self.luapage_pointers_file = line.get('luapage_pointers_file', None)
                    self.byfron_analysis = line.get('byfron_analysis', False)
                    self.save_state_file = line.get('save_state_file', None)
                    self.dmp_file = line.get('dmp_file', None)
                    self.radare_file = line.get('radare_file', None)
                    continue
                addr = d['addr']
                ecls = eval(d['type'])
                is_tval = d['type'].find('LuauRW_TValue') != -1
                is_lua_page = d['type'].find('LuauRW_lua_Page') != -1
                if hasattr(ecls, 'from_analysis'):
                    lco = ecls.from_analysis(addr, self)
                    if lco.is_gco():
                        self.add_gc_object(addr, lco)
                        gcos[lco.addr] = lco
                        if 'printable_string' in d and d['printable_string']:
                            self.printable_strings[lco.addr] = lco
                    elif not is_lua_page:
                        self.add_struct_object(addr, lco)
                        self.lua_pages.add_page(lco, walk_pages=False)
                    elif not is_tval:
                        self.add_struct_object(addr, lco)
                        tvals.append(lco)
                    else:
                        self.add_struct_object(addr, lco)

                    added_addrs.add(d['addr'])

                if 'references' in d and d['addr'] in added_addrs:
                    hold_references.append(d)

            self.log.debug("Updating lua pages with {} tvalues".format(len(tvals)))
            for tval in tvals:
                self.lua_pages.add_tvalue(tval)

            self.log.debug("Updating lua pages with {} objects".format(len(gcos)))
            for gco in gcos.values():
                self.lua_pages.add_obj(gco)

            self.log.debug("Updating lua pages with {} object references".format(len(hold_references)))
            for refs_line in hold_references:
                addr = refs_line['addr']
                for raddr in refs_line['references']:
                    self.add_gco_reference(addr, raddr)

            self.log.debug("Completed loading state from {}".format(inputfile))
        return True

    def get_objects_in_anchor_section(self, obj_tt=None) -> [LuauSifterResult | LuauByfronSifterResult]:
        if len(self.anchor_sections) == 0:
            self.find_anchor_pages()

        pot_objects = self.get_potential_objects_from_sifter(obj_tt)
        mrs = [i['memory_range'] for i in self.anchor_sections.values()]
        results = [i for i in pot_objects if any([mr.vaddr <= i.addr < mr.vaddr + mr.vsize for mr in mrs])]
        return results

    def associate_thread_and_global_state(self):
        threads = self.get_threads()
        for thread in threads.values():
            gs = getattr(thread, 'global_State')
            if gs == 0 or not self.valid_vaddr(gs):
                self.state_association[gs] = {'global_State': '', 'thread': thread}
                continue
            self.state_association[thread.addr] = {'global_State': LuauRWB_global_State.from_analysis(gs, self, safe_load=False),
                                 'thread': thread}
        return self.state_association

    @classmethod
    def init_from(cls, base_directory, bin_name, load_pointers=False, scan=False, byfron_analysis=True):
        from overlay_prototyping.luau_roblox import consts
        reset_global_deps(base_directory)
        dmp_file = DUMP_FMT.format(**{"base_dir": consts.BINS_DIR, 'bin_name': bin_name, "dmp_ext": consts.DUMP_EXT})
        pointers_file = POINTERS_FMT.format(**{"base_dir": consts.SEARCHES_DIR, 'bin_name': bin_name})
        lua_pointers_file = LUAPAGE_POINTER_FMT.format(**{"base_dir": consts.SEARCHES_DIR, 'bin_name': bin_name})
        radare_memory_info_file = MEMORY_INFO_FMT.format(**{"base_dir": consts.MEMS_DIR, 'bin_name': bin_name})
        saved_state = SAVED_OBJECTS_FILE.format(**{"base_dir": consts.SEARCHES_DIR, 'bin_name': bin_name})
        analysis = LuauRobloxAnalysis(dmp_file=dmp_file,
                                      radare_file_data=radare_memory_info_file,
                                      sift_results=pointers_file,
                                      luapage_pointers_file=lua_pointers_file,
                                      byfron_analysis=byfron_analysis,
                                      save_state=saved_state)
        if scan:
            lpscan_results = analysis.scan_lua_pages_gco(add_obj=True)
            tvals = analysis.scan_lua_pages_tvalue(add_obj=True)
        if load_pointers:
            analysis.load_sift_results()
            while True:
                if analysis.check_results_status() and analysis.check_analysis_status():
                    break
                time.sleep(.5)
        return analysis

