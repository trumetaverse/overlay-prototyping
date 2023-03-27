from ..analysis import Analysis
from ..base import BaseException
from .luau_roblox_tstring import LuauRobloxTstring
from .enumerate_luau_roblox import LuauSifterResults


class LuauRobloxAnalysis(Analysis):

    def __init__(self, sift_results=None, **kargs):
        super(LuauRobloxAnalysis, self).__init__(**kargs)
        self.lrss = None
        self.objects = {}
        self.strings = {}
        self.prims = {}

        self.raw_sift_results = sift_results
        self.sift_results_loaded = False

    def add_object(self, obj):
        if obj is None:
            return
        vaddr = obj.addr
        self.objects[vaddr] = obj
        if obj.is_string():
            self.strings[vaddr] = obj

        if obj.is_prim():
            self.prims[vaddr] = obj

    def get_strings(self):
        return sorted([self.strings[k] for k in sorted(self.strings)])

    def load_sift_results(self, pointer_file=None):
        if self.raw_sift_results is None and pointer_file is None:
            raise BaseException("No sift results file set")

        if self.raw_sift_results is None:
            self.raw_sift_results = pointer_file

        self.lrss = LuauSifterResults()
        self.lrss.parse_file(pointer_file)
        self.sift_results_loaded = True

    def find_lua_strings_from_sift_file(self, pointer_file):
        if not self.memory_loaded:
            self.load_memory()

        if not self.sift_results_loaded:
            self.load_sift_results()

        pot_tstrings = self.lrss.get_potential_tstrings()

        for ts in pot_tstrings:
            vaddr = ts.sink_vaddr
            if vaddr in self.strings:
                continue
            data = self.read_vaddr(vaddr, self.DEFAULT_OBJECT_READ_SZ)
            s = LuauRobloxTstring.from_bytes(vaddr, data, analysis=self, is_32bit=True)
            if s.probably_valid_string():
                self.add_object(s)

        return self.get_strings()
