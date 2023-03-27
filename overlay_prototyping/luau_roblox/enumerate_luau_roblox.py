import json
from .luau_roblox_base import LuauRobloxBase, TYPES, VALID_MARKS

LUAR_FILTERS = {
    "addr_is_lua_object": lambda lsr: lsr.sink_vaddr % 8 == 0,
    # "value_is_lua_object": lambda lsr: lsr.sink_value is not None and lsr.sink_value % 8 == 0,
}

class LuauSifterResults(object):
    def __init__(self):
        self.srcs = {}
        self.pot_objects = {}
        self.distinct_values = {}
        self.potential_gcheaders = {}
        self.densities = {}
        self.types = {}



    def add_sifter_result(self, r):
        if not r.sink_vaddr in self.pot_objects and r.is_valid_gc_header():
            self.pot_objects[r.sink_vaddr] = r
            if r.sink_vaddr_base not in self.densities:
                self.densities[r.sink_vaddr_base] = set()
                self.types[r.sink_vaddr_base] = {k: set() for k in range(0, 0xd)}
            self.densities[r.sink_vaddr_base].add(r.sink_vaddr)
            self.types[r.sink_vaddr_base][r.tt].add(r.sink_vaddr)

        if r.sink_value not in self.distinct_values:
            self.distinct_values[r.sink_value] = 0
        self.distinct_values[r.sink_value] += 1

        if r.sink_vaddr not in self.srcs:
            self.srcs[r.sink_vaddr] = []

        self.srcs[r.sink_vaddr].append({'vaddr': r.vaddr, 'paddr': r.paddr})


    def parse_line(self, line, parse_gc_header=False):
        r = LuauSifterResult.from_line(line, parse_gc_header=parse_gc_header)
        if r.potential_lua_object():
            self.add_sifter_result(r)
        return r

    def parse_file(self, filename, parse_gc_header=False):
        fh = open(filename)
        cnt = 0
        for line in fh:
            self.parse_line(line, parse_gc_header=parse_gc_header)
            cnt += 1

    def get_potential_tstrings(self):
        return sorted([i for i in self.pot_objects if i.tt == 5 and i.marked > 0], key=lambda u: u.sink_vaddr)


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
            self.gcheader = LuauRobloxBase.from_int(self.sink_vaddr, self.sink_value)

    def is_valid_gc_header(self):
        return self.tt in TYPES and self.marked in VALID_MARKS and self.padding == 0
    def valid_gcheader(self):
        # return self.gcheader is not None and self.gcheader.is_valid_gc_header()
        return self.is_valid_gc_header()

    @classmethod
    def from_line(cls, line, parse_gc_header=False):
        r = json.loads(line)
        return cls(parse_gc_header=parse_gc_header, **r)

    def potential_lua_object(self):
        return all(v(self) for v in LUAR_FILTERS.values())

    def __str__(self):
        return json.dumps(self.__dict__)

    def __repr__(self):
        return str(self)

