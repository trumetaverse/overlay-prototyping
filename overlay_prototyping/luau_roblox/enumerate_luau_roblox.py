import json

from .consts import *

LUAR_FILTERS = {
    "addr_is_lua_object": lambda lsr: lsr.sink_vaddr % 8 == 0,
    # "value_is_lua_object": lambda lsr: lsr.sink_value is not None and lsr.sink_value % 8 == 0,
}


class LuauSifterResult(object):
    KEY_VALUES = ["paddr",
                  "vaddr",
                  "sink_vaddr",
                  "sink_paddr",
                  "sink_value", "sink_paddr_base", "sink_vaddr_base", "vaddr_base", "paddr_base"
                  ]

    _fields_alias_ = {
        "gch_tt": "gch_field_0",
        "gch_marked": "gch_field_1",
        "gch_memcat": "gch_field_2",
        "gch_padding": "gch_field_3"
    }
    def __init__(self, **kargs):
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
        self.padding = -1

        for k, v in kargs.items():
            if k in self.KEY_VALUES and v != "null":
                setattr(self, k, int(v, 16))
            elif k in self.KEY_VALUES and v == "null":
                setattr(self, k, None)
            else:
                setattr(self, k, v)

        if isinstance(self.sink_value, int):
            self.gch_field_0 = (self.sink_value & 0x000000ff)
            self.gch_field_1 = (self.sink_value & 0x0000ff00) >> 8
            self.gch_field_2 = (self.sink_value & 0x00ff0000) >> 16
            self.gch_field_03 = (self.sink_value & 0xff000000) >> 24

    @classmethod
    def update_alias_by_ordered_list(cls, alias_fields=None):
        af = alias_fields if alias_fields else GCH_FIELD_DEFAULT_ORDER
        x = {k:v for k, v in zip(af, GCH_ORDERED_FIELDS[:len(af)])}
        if len(x) > 0:
            cls._fields_alias_.update(x)
        return cls._fields_alias_

    @classmethod
    def update_alias_by_dict(cls, **kargs):
        for k, v in kargs.items():
            if isinstance(k, str) and isinstance(v, str):
                cls._fields_alias_[k] = v

    def unalias_field(self, fld_name):
        return getattr(self, fld_name, None)

    @property
    def tt(self):
        return self.unalias_field('gch_tt')

    @property
    def marked(self):
        return self.unalias_field('gch_marked')

    @property
    def memcat(self):
        return self.unalias_field('gch_memcat')

    @property
    def gch_padding(self):
        return self.unalias_field('gch_padding')

    def is_valid_gc_header(self) -> bool:
        return self.tt in VALID_OBJ_TYPES and self.marked in VALID_MARKS and self.padding == 0

    def valid_gcheader(self) -> bool:
        # return self.gcheader is not None and self.gcheader.is_valid_gc_header()
        return self.is_valid_gc_header()

    @classmethod
    def from_line(cls, line, parse_gc_header=False):
        r = json.loads(line)
        return cls(**r)

    def potential_lua_object(self):
        # return all(v(self) for v in self.)
        # if self.tt == TSTRING and self.sink_vaddr % 8 != 0:
        # hold this constraint for all objects
        if self.sink_vaddr % 8 != 0:
            return False
        return self.is_valid_gc_header()

    def __str__(self):
        return json.dumps(self.__dict__)

    def __repr__(self):
        return str(self)


class LuauSifterResults(object):
    def __init__(self, byfron_sift_results=False):
        self.gco_srcs = {}
        self.obj_references = {}
        self.all_pot_gco = {}
        self.potential_gcheaders = {}
        self.densities_gco = {}
        self.gco_results = {}
        self.unknown_gcos = {}
        self.struct_srcs = {}
        self.struct_results = {}

        self.pot_lua_gco = {
            k: {} for k in VALID_OBJ_TYPES
        }

        self.SifterResultCls = LuauSifterResult # if not byfron_sift_results else LuauByfronSifterResult

    def add_pot_gco_sifter_result(self, r):
        self.gco_results[r.vaddr] = r
        if r.is_valid_gc_header():
            self.all_pot_gco[r.sink_vaddr] = r
            self.pot_lua_gco[r.tt][r.sink_vaddr] = r
            if r.sink_vaddr not in self.obj_references:
                self.obj_references[r.sink_vaddr] = set()

            self.obj_references[r.sink_vaddr].add(r.vaddr)
            if r.sink_vaddr_base not in self.densities_gco:
                self.densities_gco[r.sink_vaddr_base] = set()
            self.densities_gco[r.sink_vaddr_base].add(r.sink_vaddr)

        else:
            self.unknown_gcos[r.sink_vaddr] = r

        if r.sink_vaddr not in self.gco_srcs:
            self.gco_srcs[r.sink_vaddr] = []

        self.gco_srcs[r.sink_vaddr].append({'vaddr': r.vaddr, 'paddr': r.paddr})

    def add_pot_structure_sifter_result(self, r):
        self.struct_results[r.vaddr] = r
        if r.sink_vaddr not in self.struct_srcs:
            self.struct_srcs[r.sink_vaddr] = []
        self.struct_srcs[r.sink_vaddr].append({'vaddr': r.vaddr, 'paddr': r.paddr})

    def get_lua_objs(self, tt=None) -> dict[int, LuauSifterResult]:
        tts = []
        if tt is None:
            tts = list(self.pot_lua_gco.keys())

        else:
            tts = [tt]
        r = {}
        for tt in tts:
            r.update({k: v for k, v in self.pot_lua_gco[tt].itemes()})
        return r

    def get_strings(self) -> dict[int, LuauSifterResult]:
        return self.get_lua_objs(TSTRING)

    def get_udatas(self) -> dict[int, LuauSifterResult]:
        return self.get_lua_objs(TUSERDATA)

    def get_closures(self) -> dict[int, LuauSifterResult]:
        return self.get_lua_objs(TCLOSURE)

    def get_tables(self) -> dict[int, LuauSifterResult]:
        return self.get_lua_objs(TTABLE)

    def get_protos(self) -> dict[int, LuauSifterResult]:
        return self.get_lua_objs(TPROTO)

    def get_upvals(self) -> dict[int, LuauSifterResult]:
        return self.get_lua_objs(TUPVAL)

    def get_threads(self) -> dict[int, LuauSifterResult]:
        return self.get_lua_objs(TTHREAD)

    def get_potential_objects(self) -> list[LuauSifterResult]:
        return sorted(self.all_pot_gco.values(), key=lambda x: x.sink_vaddr)

    def parse_line(self, line) -> LuauSifterResult:
        r = self.SifterResultCls.from_line(line)
        if r.potential_lua_object():
            self.add_pot_gco_sifter_result(r)
        else:
            self.add_pot_structure_sifter_result(r)
        return r

    def parse_file(self, filename, bulk_load=True, callback=None):
        fh = open(filename)
        if bulk_load:
            data = fh.readlines()
            for line in data:
                self.parse_line(line)
        else:
            cnt = 0
            for line in fh:
                self.parse_line(line)
                cnt += 1

        if callback:
            callback()

    def get_potential_tstrings(self) -> list[LuauSifterResult]:
        pot_objects = list(self.all_pot_gco.values())
        return sorted([i for i in pot_objects if i.tt == TSTRING and i.marked in VALID_MARKS],
                      key=lambda u: u.sink_vaddr)
