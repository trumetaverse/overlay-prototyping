import json

from .consts import *
from .luau_roblox_overlay import LuauRW_GCHeader

LUAR_FILTERS = {
    "addr_is_lua_object": lambda lsr: lsr.sink_vaddr % 8 == 0,
    # "value_is_lua_object": lambda lsr: lsr.sink_value is not None and lsr.sink_value % 8 == 0,
}


class LuauSifterResults(object):
    def __init__(self):
        self.srcs = {}
        self.obj_references = {}
        self.pot_objects = {}
        self.distinct_values = {}
        self.potential_gcheaders = {}
        self.densities = {}
        self.results = {}
        self.pot_closures = {}
        self.pot_upvals = {}
        self.pot_userdata = {}
        self.pot_strings = {}
        self.pot_tables = {}
        self.pot_prototype = {}
        self.unknown = {}
        self.tag_objects = {
            TSTRING: self.pot_strings,
            TTABLE: self.pot_tables,
            TUPVAL: self.pot_upvals,
            TUSERDATA: self.pot_userdata,
            TPROTO: self.pot_prototype,
            TCLOSURE: self.pot_closures,
        }

    def add_sifter_result(self, r):
        self.results[r.vaddr] = r
        if r.is_valid_gc_header() and r.tt in self.tag_objects and r.marked in VALID_MARKS:
            self.pot_objects[r.sink_vaddr] = r
            self.tag_objects[r.tt][r.sink_vaddr] = r
            if r.sink_vaddr not in self.obj_references:
                self.obj_references[r.sink_vaddr] = set()

            self.obj_references[r.sink_vaddr].add(r.vaddr)
            if r.sink_vaddr_base not in self.densities:
                self.densities[r.sink_vaddr_base] = set()
            self.densities[r.sink_vaddr_base].add(r.sink_vaddr)

        else:
            self.unknown[r.sink_vaddr] = r

        if r.sink_value not in self.distinct_values:
            self.distinct_values[r.sink_value] = 0
        self.distinct_values[r.sink_value] += 1

        if r.sink_vaddr not in self.srcs:
            self.srcs[r.sink_vaddr] = []

        self.srcs[r.sink_vaddr].append({'vaddr': r.vaddr, 'paddr': r.paddr})

    def get_potential_objects(self):
        return list(self.pot_objects.values())

    def parse_line(self, line, parse_gc_header=False):
        r = LuauSifterResult.from_line(line, parse_gc_header=parse_gc_header)
        if r.potential_lua_object():
            self.add_sifter_result(r)
        return r

    def parse_file(self, filename, parse_gc_header=False, bulk_load=True):
        fh = open(filename)
        if bulk_load:
            data = fh.readlines()
            for line in data:
                self.parse_line(line, parse_gc_header=parse_gc_header)
        else:
            cnt = 0
            for line in fh:
                self.parse_line(line, parse_gc_header=parse_gc_header)
                cnt += 1

    def get_potential_tstrings(self):
        pot_objects = list(self.pot_objects.values())
        return sorted([i for i in pot_objects if i.tt == TSTRING and i.marked in VALID_MARKS],
                      key=lambda u: u.sink_vaddr)


class LuauSifterResult(object):
    KEY_VALUES = ["paddr",
                  "vaddr",
                  "sink_vaddr",
                  "sink_paddr",
                  "sink_value", "sink_paddr_base", "sink_vaddr_base", "vaddr_base", "paddr_base"
                  ]

    def __init__(self, parse_gc_header=False, **kargs):
        self.paddr = 0
        self.vaddr = 0
        self.paddr_base = 0
        self.vaddr_base = 0

        self.sink_vaddr = 0
        self.sink_paddr = 0
        self.sink_vaddr_base = 0
        self.sink_paddr_base = 0
        self.sink_value = 0
        self.gcheader = None
        self.marked = 0
        self.tt = 0
        self.memcat = 0
        self.padding = -1
        for k, v in kargs.items():
            if k in self.KEY_VALUES and v != "null":
                setattr(self, k, int(v, 16))
            elif k in self.KEY_VALUES and v == "null":
                setattr(self, k, None)
            else:
                setattr(self, k, v)

        if isinstance(self.sink_value, int):
            self.tt = (self.sink_value & 0x000000ff)
            self.marked = (self.sink_value & 0x0000ff00) >> 8
            self.memcat = (self.sink_value & 0x00ff0000) >> 16
            self.padding = (self.sink_value & 0xff000000) >> 24

        if isinstance(self.sink_value, int) and parse_gc_header:
            self.gcheader = LuauRW_GCHeader.from_int(self.sink_vaddr, self.sink_value)

    def is_valid_gc_header(self):
        return self.tt in VALID_OBJ_TYPES and self.marked in VALID_MARKS and self.padding == 0

    def valid_gcheader(self):
        # return self.gcheader is not None and self.gcheader.is_valid_gc_header()
        return self.is_valid_gc_header()

    @classmethod
    def from_line(cls, line, parse_gc_header=False):
        r = json.loads(line)
        return cls(parse_gc_header=parse_gc_header, **r)

    def potential_lua_object(self):
        # return all(v(self) for v in self.)
        if self.tt == TSTRING and self.sink_vaddr % 8 != 0:
            return False
        return self.is_valid_gc_header()

    def __str__(self):
        return json.dumps(self.__dict__)

    def __repr__(self):
        return str(self)
