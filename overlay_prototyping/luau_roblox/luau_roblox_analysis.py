import string
from threading import Thread
from ..analysis import Analysis
from ..base import BaseException
from .luau_roblox_base import LuauRobloxBase
from .luau_roblox_tstring import LuauRobloxTstring
from .enumerate_luau_roblox import LuauSifterResults
from .consts import *


class LuauRobloxAnalysis(Analysis):

    def __init__(self, sift_results=None, **kargs):
        super(LuauRobloxAnalysis, self).__init__(name="LuauRobloxAnalysis", **kargs)
        self.lrss = None
        self.objects = {}
        self.strings = {}
        self.prims = {}
        self.load_srt = None
        if not hasattr(self, 'is_32bit'):
            self.is_32bit = True

        self.raw_sift_results = sift_results
        self.sift_results_loaded = False
        self.anchor_objects = {}
        self.anchor_sections = {}
        self.objects_by_anchor_sections = {}

    def add_object_reference(self, obj_vaddr, ref_address):
        if obj_vaddr in self.objects:
            self.objects[obj_vaddr].add_reference(self, ref_address)

    def add_object(self, obj, ref_addr=None):
        if obj is None:
            return
        vaddr = obj.addr
        self.objects[vaddr] = obj
        if obj.is_string() and len(str(obj.value)) > 0:
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
        s = LuauRobloxTstring.from_bytes(vaddr, data, analysis=self, is_32bit=True)
        if s is not None and s.tt == TSTRING:
            self.add_object(s, ref_vaddr)
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
            if o.tt == tt and o.marked in VALID_MARKS:
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

    def create_class(self, name, overlay):
        return LuauRobloxBase.create_overlay(name, overlay)

    def create_object_at(self, name, overlay, vaddr, sz=8192):
        cls = LuauRobloxBase.create_overlay(name, overlay)
        data = self.read_vaddr(vaddr, sz)
        return cls.from_bytes(vaddr, data, self, self.is_32bit)

    def get_memrange(self, vaddr):
        return self.mem_ranges.get_memrange_from_vaddr(vaddr)

    def get_objects_in_section(self, vaddr):
        results = []
        mr = self.get_memrange(vaddr)
        if mr is None:
            return results

        for v in self.objects:
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
        for k,v in sinks:
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
            value = None if s is None or s.value is None else s.value
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
        if obj.marked == 0 or obj.marked not in VALID_MARKS:
            return False
        elif len(str(obj.value)) == 0 and len(obj.value) > 8:
            return False
        elif len(obj.value) > 1024 and not all([i in string.printable for i in obj.value]):
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

        anchor_ranges = [i['memory_range'] for i in self.anchor_sections.values()]
        sifter_results = self.get_potential_objects_from_sifter(obj_tt)
        check = lambda addr: any([mr.vaddr <= addr <= mr.vsize for mr in anchor_ranges])
        for sr in sifter_results:
            if check(sr.vaddr):
                results.append(sr)
        return results

    def enumerate_objects_in_anchor_sections(self):
        lua_strings = self.get_strings_from_sifter_results()
        for base_vaddr, as_json in self.anchor_sections.items():
            mr = as_json['memory_range']
            self.objects_by_anchor_sections[base_vaddr] = {'object_vaddrs': {}, 'memory_range':mr}
            addrs = [k for k in self.objects if mr.vaddr_in_range(k)]
            self.objects_by_anchor_sections[base_vaddr]['object_vaddrs'] = set(addrs)
            self.objects_by_anchor_sections[base_vaddr]['objects'] = {a: self.objects[a] for a in addrs}
            self.objects_by_anchor_sections[base_vaddr]['strings'] = {a: self.objects[a] for a in addrs}
        return self.objects_by_anchor_section


    def find_anchor_pages(self):
        ao_dict = self.find_anchor_strings()
        for ao in ao_dict.values():
            vaddr = ao.addr
            mr = self.get_memrange(vaddr)
            base_vaddr = mr.vaddr
            if base_vaddr not in self.anchor_sections:
                self.anchor_sections[base_vaddr] = {"memory_range": mr, 'cnt': 0, 'objects':{} }

            self.anchor_sections[base_vaddr]['objects'][ao.addr] = ao
            self.anchor_sections[base_vaddr]['cnt'] = len(self.anchor_sections[base_vaddr]['objects'])

        return self.anchor_sections
