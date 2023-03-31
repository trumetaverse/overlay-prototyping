import string
from threading import Thread

from .consts import *
from .enumerate_luau_roblox import LuauSifterResults
# from .luau_roblox_base import LuauRobloxBase
from .luau_roblox_overlay import LuauRW_TString
from ..analysis import Analysis, MemRange
from ..base import BaseException


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

    def add_object_reference(self, obj_vaddr, ref_address):
        obj = self.get_object(obj_vaddr)
        if obj is None:
            return

        obj.add_reference(self, ref_address)

    def add_object(self, addr, obj, ref_addr=None):
        if obj is None:
            return
        vaddr = obj.addr
        super(LuauRobloxAnalysis, self).add_object(vaddr, obj)

        if obj.is_string() and len(str(obj.get_value())) > 0:
            self.strings[vaddr] = obj

        if obj.is_prim():
            self.prims[vaddr] = obj

    def get_strings(self):
        return {k: v for k, v in self.strings.items()}

    def check_results_status(self):
        if self.sift_results_loaded:
            return True
        elif self.load_srt and self.load_srt.is_alive():
            self.log.debug("Still loading {} results from {}".format(len(self.lrss.results), self.raw_sift_results))
            return False
        self.log.debug("Completed loading {} results from {}".format(len(self.lrss.results), self.raw_sift_results))
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
        kwargs = {'parse_gc_header': False, 'bulk_load': bulk_load}
        self.load_srt = Thread(target=self.lrss.parse_file, kwargs=kwargs, args=(self.raw_sift_results,))
        self.load_srt.start()
        if not background:
            self.load_srt.join()
        return self.check_results_status()
        # self.lrss.parse_file(self.raw_sift_results)
        # self.sift_results_loaded = True

    def add_string_at_vaddr(self, vaddr, ref_vaddr=None):
        if vaddr in self.strings:
            return self.strings[vaddr]
        data = self.read_vaddr(vaddr, self.DEFAULT_OBJECT_READ_SZ)
        s = LuauRW_TString.from_bytes(vaddr, data, analysis=self, word_sz=self.word_sz)
        if s is not None and s.is_valid_gc_header() and s.get_gch().tt == TSTRING:
            self.add_object(s.addr, s, ref_vaddr)
        return s

    def find_lua_strings_from_sift_file(self):
        if not self.memory_loaded:
            self.load_memory()

        if not self.sift_results_loaded:
            self.load_sift_results()

        return self.get_strings_from_sifter_results()

    def get_potential_objects_from_sifter(self, tt):
        results = []
        for o in self.lrss.get_potential_objects():
            # this is a sifter result and not an object
            if o.is_valid_gc_header() and o.tt == tt:
                results.append(o)
        return results

    def potentials_tstrings(self):
        return self.get_potential_objects_from_sifter(TSTRING)

    def potentials_closures(self):
        return self.get_potential_objects_from_sifter(TCLOSURE)

    def potentials_userdata(self):
        return self.get_potential_objects_from_sifter(TUSERDATA)

    def potentials_thread(self):
        return self.get_potential_objects_from_sifter(TTHREAD)

    def potentials_table(self):
        return self.get_potential_objects_from_sifter(TTABLE)

    def potentials_prototypes(self):
        return self.get_potential_objects_from_sifter(TPROTO)

    def potentials_upvals(self):
        return self.get_potential_objects_from_sifter(TUPVAL)

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
        sinks = self.lrss.results.values()
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
        sinks = self.lrss.results.items()
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

    def find_anchor_strings(self):
        if not self.is_sift_results_loaded():
            self.load_sift_results()
        lua_strings = self.get_strings_from_sifter_results()

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
        return self.anchor_objects

    def check_string(self, obj):
        value = obj.get_value() if hasattr(obj, 'get_value') else None
        if obj.marked == 0 or obj.marked not in VALID_MARKS:
            return False
        elif len(str(value)) == 0 and len(value) > 8:
            return False
        elif len(value) > 1024 and not all([i in string.printable for i in value]):
            return False
        return True

    def get_safe_strings(self):
        lua_strings = self.get_strings_from_sifter_results()
        results = {}
        for addr, obj in lua_strings.items():
            if self.check_string(obj):
                results[addr] = obj
        return results

    def get_objects_in_anchor_section(self, obj_tt):
        results = []
        if len(self.anchor_sections) == 0:
            self.find_anchor_pages()

        pot_objects = self.get_potential_objects_from_sifter(obj_tt)
        mrs = [i['memory_range'] for i in self.anchor_sections.values()]
        results = [i for i in pot_objects if any([mr.vaddr <= i.sink_vaddr < mr.vaddr + mr.vsize for mr in mrs])]
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
