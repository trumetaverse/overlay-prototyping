import json

LUAR_FILTERS = {
    "addr_is_lua_object": lambda lsr: lsr.sink_vaddr % 8 == 0,
    # "value_is_lua_object": lambda lsr: lsr.sink_value is not None and lsr.sink_value % 8 == 0,
}

class LuauSifterResults(object):
    def __init__(self):
        self.srcs = {}
        self.pot_objects = {}
        self.distinct_values = {}

    def add_sifter_result(self, r):
        if not r.sink_vaddr in self.pot_objects:
            self.pot_objects[r.sink_vaddr] = r

        if r.sink_value not in self.distinct_values:
            self.distinct_values[r.sink_value] = 0
        self.distinct_values[r.sink_value] += 1

        if r.sink_vaddr not in self.srcs:
            self.srcs[r.sink_vaddr] = []

        self.srcs[r.sink_vaddr].append({'vaddr': r.vaddr, 'paddr': r.paddr})

    def parse_line(self, line):
        r = LuauSifterResult.from_line(line)
        if r.potential_lua_object():
            self.add_sifter_result(r)
        return r

    def parse_file(self, filename):
        fh = open(filename)
        cnt = 0
        for line in fh:
            self.parse_line(line)
            cnt += 1


class LuauSifterResult(object):
    KEY_VALUES = ["paddr",
    "vaddr",
    "sink_vaddr",
    "sink_paddr",
    "sink_value"]

    def __init__(self, **kargs):
        self.paddr = 0
        self.vaddr = 0
        self.sink_vaddr = 0
        self.sink_paddr = 0
        self.sink_value = 0
        for k, v in kargs.items():
            if k in self.KEY_VALUES and v != "null":
                setattr(self, k, int(v, 16))
            elif k in self.KEY_VALUES and v == "null":
                setattr(self, k, None)
            else:
                setattr(self, k, v)

    @classmethod
    def from_line(cls, line):
        r = json.loads(line)
        return cls(**r)

    def potential_lua_object(self):
        return all(v(self) for v in LUAR_FILTERS.values())

    def __str__(self):
        return json.dumps(self.__dict__)

    def __repr__(self):
        return str(self)

