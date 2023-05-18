import json
from overlay_prototyping.luau_roblox.luau_roblox_analysis import LuauRobloxAnalysis
from overlay_prototyping.luau_roblox.enumerate_luau_roblox import LuauSifterResult, LuauSifterResults
from overlay_prototyping.luau_roblox.consts import *
from overlay_prototyping.luau_roblox.overlay_base import *
from overlay_prototyping.luau_roblox.overlay_byfron import *

analysis = LuauRobloxAnalysis.init_from('/research_data/dumps/2023-04-28/', bin_name='dso_hack2-10', gch_field_order=['gch_padding', 'gch_marked', 'gch_tt', 'gch_memcat'], tstring_len_calc='add_end_addr_value')
analysis.restore_state(analysis.save_state_file)
lps = analysis.load_lua_pages()
analysis.restore_state(analysis.save_state_file)
strings = analysis.get_printable_strings()
chunk_names = [(i.addr, i.get_value()) for i in analysis.get_strings().values() if isinstance(i.get_value(), str) and i.get_value().find('=') == 0]
len(set(chunk_names))
open('chunk_names.txt', 'w').write('\n'.join(["{:08x}, {}".format(addr, cn) for addr, cn in chunk_names]))
analysis2 = LuauRobloxAnalysis.init_from('/research_data/dumps/2023-04-28/', bin_name='dso_hack2-00-transition', gch_field_order=['gch_padding', 'gch_marked', 'gch_tt', 'gch_memcat'], tstring_len_calc='add_end_addr_value')
lps = analysis2.load_lua_pages()
analysis2.restore_state(analysis2.save_state_file)
chunk_names2 = [(i.addr, i.get_value()) for i in analysis2.get_strings().values() if isinstance(i.get_value(), str) and i.get_value().find('=') == 0]
len(chunk_names2)
chunk_names2 = [(i.addr, i.get_value()) for i in analysis2.get_printable_strings().values() if isinstance(i.get_value(), str) and i.get_value().find('=') == 0]
analysis3 = LuauRobloxAnalysis.init_from('/research_data/dumps/2023-04-28/', bin_name='dso_hack2-01', gch_field_order=['gch_padding', 'gch_marked', 'gch_tt', 'gch_memcat'], tstring_len_calc='add_end_addr_value')
lps = analysis3.load_lua_pages()
analysis3.restore_state(analysis3.save_state_file)
