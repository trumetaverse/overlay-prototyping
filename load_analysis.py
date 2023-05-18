import json
from overlay_prototyping.luau_roblox.luau_roblox_analysis import LuauRobloxAnalysis
from overlay_prototyping.luau_roblox.enumerate_luau_roblox import LuauSifterResult, LuauSifterResults
from overlay_prototyping.luau_roblox.consts import *
from overlay_prototyping.luau_roblox.overlay_base import *
from overlay_prototyping.luau_roblox.overlay_byfron import *

analysis = LuauRobloxAnalysis.init_from('/research_data/dumps/2023-04-28/', bin_name='dso_hack3-01', gch_field_order=['gch_padding', 'gch_marked', 'gch_tt', 'gch_memcat'], tstring_len_calc='add_end_addr_value')
analysis.restore_state(analysis.save_state_file)
lps = analysis.load_lua_pages()
analysis.restore_state(analysis.save_state_file)
