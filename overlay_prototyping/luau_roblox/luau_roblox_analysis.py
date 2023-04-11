import ctypes
import string
from threading import Thread

from .consts import *
from .enumerate_luau_roblox import LuauSifterResults, LuauSifterResult
# from .luau_roblox_base import LuauRobloxBase
from .overlay_base import LuauRW_BaseStruct, LuauRW_TString, LuauRW_lua_State, LuauRW_Udata, LuauRW_Proto, LuauRW_Table, \
    LuauRW_UpVal, LuauRW_Closure, VALID_OBJ_CLS_MAPPING, LuauRW_GCHeader, LuauRW_TValue, LuauRW_global_State, \
    LuauRW_lua_Page
from ..analysis import Analysis, MemRange
from ..base import BaseException

GCO_TT_MAPPING = {
    TSTRING: LuauRW_TString,
    TUPVAL: LuauRW_UpVal,
    TTHREAD: LuauRW_lua_State,
    TCLOSURE: LuauRW_Closure,
    TTABLE: LuauRW_Table,
    TPROTO: LuauRW_Proto,
    TUSERDATA: LuauRW_Udata
}

GCO_NAME_MAPPING = {
    TSTRING: LuauRW_TString,
    TUPVAL: LuauRW_UpVal,
    TTHREAD: LuauRW_lua_State,
    TCLOSURE: LuauRW_Closure,
    TTABLE: LuauRW_Table,
    TPROTO: LuauRW_Proto,
    TUSERDATA: LuauRW_Udata,
}


class LuauRobloxAnalysis(Analysis):

    def __init__(self, sift_results=None, **kargs):
        super(LuauRobloxAnalysis, self).__init__(name="LuauRobloxAnalysis", **kargs)
        self.lrss = None
        self.strings = {}
        self.prims = {}
        self.load_srt = None
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

        self.safe_strings = {}

        self.lua_structs = {}
        self.not_lua_objects = {k: set() for k in VALID_OBJ_TYPES}

        self.lua_table_values = {}

    def read_table_values(self, ttable: LuauRW_Table, add_obj=False):
        sizearray = ttable.sizearray
        tvalues = {}
        for idx in range(0, sizearray):
            tva = ttable.get_tvalue_address(idx)
            tvalue = LuauRW_TValue.from_analysis(tva, self)
            tvalues[tvalue.addr] = tvalue
            if add_obj:
                self.add_struct_object(tva, tvalue)
        return tvalues

    def add_gc_object(self, addr, obj, ref_addr=None, override_safe_check=True):
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

        if obj.is_string() and len(str(obj.get_value())) > 0:
            if override_safe_check or self.check_string(obj):
                self.safe_strings[vaddr] = obj


    def get_lua_objs_by_memcat(self, memcat, tt=None):
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

    def get_lua_objs(self, tt=None, memcat=None):
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

    def get_lua_object(self, vaddr, tt=None):
        if tt is not None and vaddr in self.lua_gco[tt]:
            return self.lua_gco[tt][vaddr]
        for gcos in self.lua_gco.values():
            if vaddr in gcos:
                return gcos[vaddr]
        return None

    def get_strings(self):
        return self.get_lua_objs(TSTRING)

    def get_udatas(self):
        return self.get_lua_objs(TUSERDATA)

    def get_closures(self):
        return self.get_lua_objs(TCLOSURE)

    def get_tables(self):
        return self.get_lua_objs(TTABLE)

    def get_protos(self):
        return self.get_lua_objs(TPROTO)

    def get_upvals(self):
        return self.get_lua_objs(TUPVAL)

    def get_threads(self):
        return self.get_lua_objs(TTHREAD)

    def check_results_status(self):
        if self.sift_results_loaded:
            return True
        elif self.load_srt and self.load_srt.is_alive():
            self.log.debug(
                "Still loading. loaded potential gcos from {} and potential structs {} results from {}".format(
                    len(self.lrss.gco_results), len(self.lrss.struct_results), self.raw_sift_results))
            return False
        self.log.debug("Completed. loaded potential gcos from {} and potential structs {} results from {}".format(
                    len(self.lrss.gco_results), len(self.lrss.struct_results), self.raw_sift_results))
        self.sift_results_loaded = True
        self.load_srt = None
        return True

    def is_sift_results_loaded(self):
        return self.sift_results_loaded

    def load_sift_results(self, pointer_file=None, background=True, bulk_load=True):
        if self.raw_sift_results is None and pointer_file is None:
            raise BaseException("No sift results file set")

        if self.load_srt is not None:
            return self.check_results_status()

        if self.raw_sift_results is None:
            self.raw_sift_results = pointer_file

        self.log.debug("Loading luau-sifter results from {}".format(self.raw_sift_results))
        self.lrss = LuauSifterResults()
        kwargs = {'parse_gc_header': False, 'bulk_load': bulk_load, 'callback':self.check_results_status}
        self.load_srt = Thread(target=self.lrss.parse_file, kwargs=kwargs, args=(self.raw_sift_results, ))
        self.load_srt.start()
        if not background:
            self.load_srt.join()
        return self.check_results_status()
        # self.lrss.parse_file(self.raw_sift_results)
        # self.sift_results_loaded = True

    def get_gco_overlay(self, vaddr, ctypes_cls, buf=None, ref_addr=None, add_obj=False, caution=False):
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

    def add_string_at_vaddr(self, vaddr, ref_vaddr=None):
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

    def read_gco(self, vaddr, tt=None, add_obj=False, caution=False) -> [object | None]:
        if tt is None:
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
        return self.get_gco_overlay(vaddr, cls, add_obj=add_obj, caution=caution)

    def read_tvalue(self, vaddr, index=0, add_obj=False, caution=False) -> [object | None]:
        tv = LuauRW_TValue.from_analysis(vaddr, self)
        return tv

    def read_gco_ptr(self, pvaddr, tt=None, word_sz=4, little_endian=True, add_obj=False, caution=False) -> [
        object | None]:
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
                        add_obj=False) -> [object | None]:
        if obj_cls.is_gco():
            return self.read_gco_ptr(pvaddr, obj_cls._tt_, word_sz, little_endian, add_obj)

        vaddr = self.deref_address(pvaddr, word_sz, little_endian)
        if vaddr is None:
            return None

        obj = obj_cls.from_analysis(vaddr, self)
        if obj is not None and obj.sanity_check() and add_obj:
            self.add_gc_object(vaddr, obj, pvaddr)
        return obj

    def find_lua_strings_from_sift_file(self):
        if not self.memory_loaded:
            self.load_memory()

        if not self.sift_results_loaded:
            self.load_sift_results()

        return self.get_strings_from_sifter_results()

    def get_potential_objects_from_sifter(self, tt, perform_overlay=True, add_obj=False):
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

    def potentials_tstrings(self, sanity_check=False, add_obj=False):
        tstrings = self.get_potential_objects_from_sifter(TSTRING)
        if add_obj:
            for o in tstrings:
                self.add_gc_object(o.addr, o)
        return tstrings

    def potentials_closures(self, sanity_check=False, add_obj=False):
        r = self.get_potential_objects_from_sifter(TCLOSURE)
        if sanity_check:
            tables = self.potentials_table(sanity_check=sanity_check)
            dtables = {i.addr: i for i in tables}
            closures = []
            for obj in r:
                if self.valid_vaddr(obj.env):
                    c_env = LuauRW_Table.from_analysis(obj.env, self)
                    if c_env and c_env.addr in dtables:
                        closures.append(obj)
            if add_obj:
                for o in closures:
                    self.add_gc_object(o.addr, o)
            return closures
        return r

    def potentials_userdata(self, sanity_check=False, add_obj=False):
        r = self.get_potential_objects_from_sifter(TUSERDATA)
        if sanity_check:
            tables = self.potentials_table(sanity_check=sanity_check)
            dtables = {i.addr: i for i in tables}
            userdatas = []
            for obj in r:
                if self.valid_vaddr(obj.metatable):
                    mt = LuauRW_Table.from_analysis(obj.metatable, self)
                    if mt and mt.addr in dtables:
                        userdatas.append(obj)
            if add_obj:
                for o in userdatas:
                    self.add_gc_object(o.addr, o)
            return userdatas
        return r

    def potentials_thread(self, sanity_check=False, add_obj=False):
        r = self.get_potential_objects_from_sifter(TTHREAD)
        if sanity_check:
            threads = []
            for obj in r:
                global_state = self.valid_vaddr(getattr(obj, 'global'))
                call_info = self.valid_vaddr(obj.ci)
                stack = self.valid_vaddr(obj.stack)
                stack_last = self.valid_vaddr(obj.stack_last)
                gt = self.valid_vaddr(obj.gt)
                all_checks = [global_state, call_info, stack, stack_last, gt]
                if all(all_checks):
                    threads.append(obj)
            if add_obj:
                for o in threads:
                    self.add_gc_object(o.addr, o)
            return threads
        return r

    def potentials_table(self, sanity_check=False, add_obj=False):
        r = self.get_potential_objects_from_sifter(TTABLE)
        if sanity_check:
            tables = {}
            dt = {i.addr: i for i in r}
            for t in r:
                if self.valid_vaddr(t.metatable) and t.metatable in dt:
                    tables[t.addr] = t
                    tables[t.metatable] = t
            tables = list(tables.values())
            if add_obj:
                for o in tables:
                    self.add_gc_object(o.addr, o)
            return tables
        return r

    def potentials_prototypes(self, sanity_check=False, add_obj=False):
        return self.get_potential_objects_from_sifter(TPROTO)

    def potentials_upvals(self, sanity_check=False, add_obj=False):
        r = self.get_potential_objects_from_sifter(TUPVAL)
        if sanity_check:
            upvals = []
            for obj in r:
                if self.valid_vaddr(obj.v):
                    tvalue = LuauRW_TValue.from_analysis(obj.v, self)
                    if tvalue and tvalue.tt in VALID_OBJ_CLS_MAPPING:
                        upvals.append(obj)
            if add_obj:
                for o in upvals:
                    self.add_gc_object(o.addr, o)
            return upvals
        return r

    def find_potential_global_state(self, pot_threads=None):
        globals_results = {}
        pot_threads = self.potentials_thread() if pot_threads is None else pot_threads
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

    def get_memrange(self, vaddr):
        return self.mem_ranges.get_memrange_from_vaddr(vaddr)

    def get_objects_in_section(self, vaddr):
        results = []
        mr = self.get_memrange(vaddr)
        if mr is None:
            return results

        for v in self.get_object_addresses():
            addr = v.sink_vaddr
            if mr.start <= addr < mr.end:
                results.append(v)
        return results

    def get_pot_objects_in_section(self, vaddr):
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

    def get_sinks_in_section(self, vaddr):
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

    def get_srcs_in_section(self, vaddr):
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

    def get_strings_from_sifter_results(self):
        pot_tstrings = self.lrss.get_potential_tstrings()
        for ts in pot_tstrings:
            vaddr = ts.sink_vaddr
            if vaddr in self.strings:
                continue
            ref_vaddr = ts.vaddr
            self.add_string_at_vaddr(vaddr, ref_vaddr=ref_vaddr)
        return self.get_strings()

    def get_builtin_strings_from_sifter_results(self):
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

    def find_anchor_strings(self):
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

    def find_anchor_objects(self):
        self.anchor_objects = {}
        if not self.is_sift_results_loaded():
            self.load_sift_results()

        # lua_strings
        self.find_anchor_strings()
        self.find_anchor_pages()

        # now that we have anchor pages
        # find all gco threads
        return self.anchor_objects

    def check_string(self, obj):
        if obj.addr in self.safe_strings:
            return True
        value = None if not isinstance(obj, LuauRW_TString) else obj.get_value()
        if value is None or len(str(value)) == 0:
            return False
        # if obj.marked == 0 or obj.marked not in VALID_MARKS:
        #     return False
        # elif len(str(value)) == 0 and len(value) > 8:
        #     return False
        elif not all([i in string.printable for i in value]):
            return False
        return True

    def get_safe_strings(self, rerun=True):
        if not rerun:
            return self.safe_strings
        lua_strings = self.get_strings_from_sifter_results()
        results = {}
        for addr, obj in lua_strings.items():
            if addr in self.safe_strings:
                results[addr] = obj
                continue
            if self.check_string(obj):
                results[addr] = obj
                self.add_gc_object(addr, obj, override_safe_check=True)
        return results

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

    def find_anchor_pages(self):
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

    def in_anchor_section(self, vaddr):
        for base, mr in self._anchor_mr:
            if mr.vaddr_in_range(vaddr):
                return True
        return False

    def get_anchor_section(self, vaddr) -> MemRange:
        for base, mr in self._anchor_mr:
            if mr.vaddr_in_range(vaddr):
                return mr
        return None

    def read_sequential_gcos_incr(analysis, start_addr, allowed_failures=0, stop_addr=None):
        gcos = {}
        stop = False

        next_addr = start_addr
        last_gco = None
        failed = allowed_failures
        while not stop:
            try:
                gco = analysis.get_gco(next_addr) if analysis.has_gco(next_addr) else analysis.read_gco(next_addr)


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

    def read_sequential_gcos_decrement(analysis, start_addr, allowed_failures=3, stop_addr=None, block_size=32):
        gcos = {}
        stop = False

        next_addr = start_addr if start_addr % 8 == 0 else start_addr - (start_addr % 8)
        last_gco = None
        failed = allowed_failures
        failures = []
        while not stop:
            try:
                gco = analysis.get_gco(next_addr) if analysis.has_gco(next_addr) else analysis.read_gco(next_addr)
            except:
                gco = None

            if failed <= 0:
                break
            value = analysis.read_uint(next_addr)
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

    def find_lua_page_header(self, start_addr=None, allowed_failures=3, stop_addr=None, block_size=32):
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

        lua_pages = []
        if lua_page is not None:
            lua_pages = []
            # walk GCO List forward
            self.log.debug(
                "Walking the lua_Page linked lists forward from at 0x{:08x}".format(lua_page.gcolistnext))
            nlp = lua_page
            while True:
                if nlp is None or nlp.gcolistnext == 0 or not self.valid_vaddr(nlp.gcolistnext):
                    break
                nlp = LuauRW_lua_Page.from_analysis(nlp.gcolistnext, analysis=self, safe_load=False)
                if nlp is not None:
                    lua_pages.append(nlp)
            # walk GCO List backward
            self.log.debug(
                "Walking the lua_Page linked lists backward from at 0x{:08x}".format(lua_page.gcolistprev))
            nlp = lua_page
            while True:
                if nlp is None or nlp.gcolistprev == 0 or not self.valid_vaddr(nlp.gcolistprev):
                    break
                nlp = LuauRW_lua_Page.from_analysis(nlp.gcolistprev, analysis=self, safe_load=False)
                if nlp is not None:
                    lua_pages.append(nlp)
            lua_pages = sorted(lua_pages, key=lambda x: x.addr)
        return lua_pages

    def get_last_page_block(self, lua_page: LuauRW_lua_Page):
        if lua_page is None:
            return None

        offset = lua_page.freeNext + lua_page.get_offset('data') + lua_page.blockSize
        return lua_page.addr + offset
