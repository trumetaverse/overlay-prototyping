import json

from .. luau_roblox.consts import *
from . overlay_byfron import LuauRWB_GCHeader
from .. luau_roblox.enumerate_luau_roblox import LuauSifterResult as OldLuauSifterResult, LuauSifterResults as OldLuauSifterResults

LUAR_FILTERS = {
    "addr_is_lua_object": lambda lsr: lsr.sink_vaddr % 8 == 0,
    # "value_is_lua_object": lambda lsr: lsr.sink_value is not None and lsr.sink_value % 8 == 0,
}



class LuauSifterResult(OldLuauSifterResult):
    KEY_VALUES = ["paddr",
                  "vaddr",
                  "sink_vaddr",
                  "sink_paddr",
                  "sink_value", "sink_paddr_base", "sink_vaddr_base", "vaddr_base", "paddr_base"
                  ]

    def __init__(self, **kargs):
        super(LuauSifterResult, self).__init__(**kargs)

        if isinstance(self.sink_value, int):
            gcheader = LuauRWB_GCHeader.from_int(self.sink_vaddr, self.sink_value)
            if isinstance(self.sink_value, int):
                self.marked = (self.sink_value & 0x000000ff)
                self.tt = (self.sink_value & 0x0000ff00) >> 8
                self.memcat = (self.sink_value & 0x00ff0000) >> 16
                self.padding = (self.sink_value & 0xff000000) >> 24


class LuauSifterResults(OldLuauSifterResults):
    def __init__(self):
        super(LuauSifterResults, self).__init__()

    def parse_line(self, line) -> LuauSifterResult:
        r = LuauSifterResult.from_line(line)
        if r.potential_lua_object():
            self.add_pot_gco_sifter_result(r)
        else:
            self.add_pot_structure_sifter_result(r)
        return r
