import os
UNINT_MAX = 4294967295
LUA_MINSTACK = 20
MAXSSIZE = (1 << 30)



UNSCRAMBLE_GCH_FIELD_0 = 'gch_field_0'
UNSCRAMBLE_GCH_FIELD_1 = 'gch_field_1'
UNSCRAMBLE_GCH_FIELD_2 = 'gch_field_2'
UNSCRAMBLE_GCH_FIELD_3 = "gch_field_3"

GCH_FIELD_DEFAULT_ORDER = ['tt', 'marked', 'memcat', 'gch_padding']
BGCH_FIELD_DEFAULT_ORDER = ['marked', 'tt', 'memcat', 'gch_padding']
GCH_ORDERED_FIELDS = [UNSCRAMBLE_GCH_FIELD_0, UNSCRAMBLE_GCH_FIELD_1, UNSCRAMBLE_GCH_FIELD_2, UNSCRAMBLE_GCH_FIELD_3]



UNSCRAMBLE_FIELD_NAME_TVALUE_TT = "tvalue_field_2"
UNSCRAMBLE_FIELD_NAME_TKEY_TT = "tkey_field_2"

FIELD_NAME_GCH_MARKED = '_field_name_gch_marked'
FIELD_NAME_GCH_TT = '_field_name_gch_tt'
FIELD_NAME_GCH_MEMCAT = '_field_name_gch_memcat'
FIELD_NAME_GCH_PADDING = "_field_name_gch_gchpadding"
FIELD_NAME_TVALUE_TT = "_field_name_tvalue_tt"
FIELD_NAME_TKEY_TT = "_field_name_tkey_tt"


DEFAULT_MAX_SIZE = MAXSSIZE/2 #536870912 # 512 MB
LUAR_ROBLOX_EVENT_NAMES = [
    "__index",
    "__newindex",
    "__mode",
    "__namecall",
    "__call",
    "__iter",
    "__len",
    "__eq",
    "__add",
    "__sub",
    "__mul",
    "__div",
    "__mod",
    "__pow",
    "__unm",
    "__lt",
    "__le",
    "__concat",
    "__type",
    "__metatable",
]

LUAR_ROBLOX_TYPES = [
    "nil",
    "boolean",
    "userdata",
    "number",
    "vector",
    "string",
    "table",
    "function",
    "userdata",
    "thread",
]

LUAR_ROBLOX_BASE_FUNCS = [
    "assert",
    "error",
    "gcinfo",
    "getfenv",
    "getmetatable",
    "next",
    "newproxy",
    "print",
    "rawequal",
    "rawget",
    "rawset",
    "rawlen",
    "select",
    "setfenv",
    "setmetatable",
    "tonumber",
    "tostring",
    "type",
    "typeof",
]

LUAUR_ALL_CONSTS = [
    "_G",
    "_LOADED",
    "_VERSION",
    "__add",
    "__call",
    "__concat",
    "__div",
    "__eq",
    "__index",
    "__iter",
    "__le",
    "__len",
    "__lt",
    "__mod",
    "__mode",
    "__mul",
    "__namecall",
    "__newindex",
    "__pow",
    "__sub",
    "__type",
    "__unm",
    "abs",
    "acos",
    "arshift",
    "asin",
    "assert",
    "atan",
    "atan2",
    "band",
    "bit32",
    "bnot",
    "boolean",
    "bor",
    "btest",
    "bxor",
    "byte",
    "ceil",
    "char",
    "charpattern",
    "clamp",
    "clock",
    "clone",
    "close",
    "codepoint",
    "codes",
    "concat",
    "coroutine",
    "cos",
    "cosh",
    "countlz",
    "countrz",
    "create",
    "date",
    "debug",
    "deg",
    "difftime",
    "error",
    "exp",
    "extract",
    "find",
    "floor",
    "fmod",
    "foreach",
    "foreachi",
    "format",
    "frexp",
    "freeze",
    "function",
    "gcinfo",
    "getfenv",
    "getinfo",
    "getmetatable",
    "getn",
    "gmatch",
    "gsub",
    "huge",
    "info",
    "insert",
    "ipairs",
    "isfrozen",
    "isyieldable",
    "ldexp",
    "len",
    "loadstring",
    "log",
    "log10",
    "lower",
    "lrotate",
    "lshift",
    "match",
    "math",
    "max",
    "maxn",
    "min",
    "modf",
    "move",
    "newproxy",
    "next",
    "nil",
    "noise",
    "number",
    "offset",
    "os",
    "pack",
    "packsize",
    "pairs",
    "pcall",
    "pi",
    "pow",
    "print",
    "rad",
    "random",
    "randomseed",
    "rawequal",
    "rawget",
    "rawset",
    "remove",
    "rep",
    "replace",
    "require",
    "resume",
    "reverse",
    "rrotate",
    "rshift",
    "running",
    "select",
    "setfenv",
    "setmetatable",
    "sign",
    "sin",
    "sinh",
    "sort",
    "split",
    "sqrt",
    "status",
    "stdin",
    "string",
    "sub",
    "table",
    "tan",
    "tanh",
    "thread",
    "time",
    "tonumber",
    "tostring",
    "traceback",
    "type",
    "typeof",
    "unpack",
    "upper",
    "userdata",
    "utf8",
    "vector",
    "wrap",
    "xpcall",
    "yield",
]



VALID_MARKS = {0, 1, 2, 4, 8, 9, 0xf}
LUA_MEMORY_CATEGORIES = 256

LUA_SIZECLASSES = 32
TNIL = 0
TBOOLEAN = 1
TLIGHTUSERDATA = 2
TNUMBER = 3
TVECTOR = 4
TSTRING = 5
TTABLE = 6
TFUNCTION = 7
TCLOSURE = 7
TUSERDATA = 8
TTHREAD = 9
TPROTO = 0xA
TUPVAL = 0xB
TDEADKEY = 0xC
LUA_T_COUNT = TPROTO

VALID_OBJ_TYPES = {
    TSTRING: "string",
    TTABLE: "table",
    # TFUNCTION: "function",
    TCLOSURE: "closure",
    TUSERDATA: "userdata",
    TTHREAD: "thread",
    TPROTO: "proto",
    TUPVAL: "upval",
    "string": TSTRING,
    "table": TTABLE,
    # "function": TFUNCTION,
    "closure": TCLOSURE,
    "userdata": TUSERDATA,
    "thread": TTHREAD,
    "proto": TPROTO,
    "upval": TUPVAL,
}

LUA_TAG_TYPES = {
    TNIL: "nil",
    TBOOLEAN: "boolean",
    TLIGHTUSERDATA: "userdata",
    TNUMBER: "number",
    TVECTOR: "vector",
    TSTRING: "string",
    TTABLE: "table",
    TCLOSURE: "closure",
    TUSERDATA: "userdata",
    TTHREAD: "thread",
}

EXTRA_STACK = 5
BASIC_CI_SIZE = 8
LUA_MINSTACK = 20
BASIC_STACK = 2 * LUA_MINSTACK
LUA_BUFFERSIZE = 512

TM_INDEX = 0
TM_NEWINDEX = 1
TM_MODE = 2
TM_NAMECALL = 3
TM_CALL = 4
TM_ITER = 5
TM_LEN = 6
TM_EQ = 7
TM_ADD = 8
TM_SUB = 9
TM_MUL = 10
TM_DIV = 11
TM_MOD = 12
TM_POW = 13
TM_UNM = 14
TM_LT = 15
TM_LE = 16
TM_CONCAT = 17
TM_TYPE = 18
TM_METATABLE = 19

TM_N = 20

TYPES = {
    0: 'TNil',
    1: 'TBoolean',
    2: 'TLightUserData',
    3: 'TNumber',
    4: 'TVector',
    5: 'TString',
    6: 'TTable',
    7: 'TFunction',
    8: 'TUserData',
    9: 'TThread',
    0xA: 'TProto',
    0xB: 'TUpVal',
    0xC: 'TDeadKey',
}

TMS = {
    TM_INDEX: "__index",
    TM_NEWINDEX: "__newindex",
    TM_MODE: "__mode",
    TM_NAMECALL: "__namecall",
    TM_CALL: "__call",
    TM_ITER: "__iter",
    TM_LEN: "__len",
    TM_EQ: "__eq",
    TM_ADD: "__add",
    TM_SUB: "__sub",
    TM_MUL: "__mul",
    TM_DIV: "__div",
    TM_MOD: "__mod",
    TM_POW: "__pow",
    TM_UNM: "__unm",
    TM_LT: "__lt",
    TM_LE: "__le",
    TM_CONCAT: "__concat",
    TM_TYPE: "__type",
    TM_METATABLE: "__metatable",
}
TMS_CNT = len(TMS)
MERGE = lambda d1, d2: d1.update(d2)

LOP_CODES = [
"LOP_NOP",
"LOP_BREAK",
"LOP_LOADNIL",
"LOP_LOADB",
"LOP_LOADN",
"LOP_LOADK",
"LOP_MOVE",
"LOP_GETGLOBAL",
"LOP_SETGLOBAL",
"LOP_GETUPVAL",
"LOP_SETUPVAL",
"LOP_CLOSEUPVALS",
"LOP_GETIMPORT",
"LOP_GETTABLE",
"LOP_SETTABLE",
"LOP_GETTABLEKS",
"LOP_SETTABLEKS",
"LOP_GETTABLEN",
"LOP_SETTABLEN",
"LOP_NEWCLOSURE",
"LOP_NAMECALL",
"LOP_CALL",
"LOP_RETURN",
"LOP_JUMP",
"LOP_JUMPBACK",
"LOP_JUMPIF",
"LOP_JUMPIFNOT",
"LOP_JUMPIFEQ",
"LOP_JUMPIFLE",
"LOP_JUMPIFLT",
"LOP_JUMPIFNOTEQ",
"LOP_JUMPIFNOTLE",
"LOP_JUMPIFNOTLT",
"LOP_ADD",
"LOP_SUB",
"LOP_MUL",
"LOP_DIV",
"LOP_MOD",
"LOP_POW",
"LOP_ADDK",
"LOP_SUBK",
"LOP_MULK",
"LOP_DIVK",
"LOP_MODK",
"LOP_POWK",
"LOP_AND",
"LOP_OR",
"LOP_ANDK",
"LOP_ORK",
"LOP_CONCAT",
"LOP_NOT",
"LOP_MINUS",
"LOP_LENGTH",
"LOP_NEWTABLE",
"LOP_DUPTABLE",
"LOP_SETLIST",
"LOP_FORNPREP",
"LOP_FORNLOOP",
"LOP_FORGLOOP",
"LOP_FORGPREP_INEXT",
"LOP_DEP_FORGLOOP_INEXT",
"LOP_FORGPREP_NEXT",
"LOP_DEP_FORGLOOP_NEXT",
"LOP_GETVARARGS",
"LOP_DUPCLOSURE",
"LOP_PREPVARARGS",
"LOP_LOADKX",
"LOP_JUMPX",
"LOP_FASTCALL",
"LOP_COVERAGE",
"LOP_CAPTURE",
"LOP_DEP_JUMPIFEQK",
"LOP_DEP_JUMPIFNOTEQK",
"LOP_FASTCALL1",
"LOP_FASTCALL2",
"LOP_FASTCALL2K",
"LOP_FORGPREP",
"LOP_JUMPXEQKNIL",
"LOP_JUMPXEQKB",
"LOP_JUMPXEQKN",
"LOP_JUMPXEQKS",
"LOP__COUNT"
]

LOP_CODES_MAPPING = {k:v for k, v in enumerate(LOP_CODES)}
MERGE (LOP_CODES_MAPPING, {v:k for k, v in enumerate(LOP_CODES)})
LOP__COUNT = LOP_CODES_MAPPING["LOP__COUNT"]

COMPILER_TYPES = [
"Type_Unknown",
"Type_Nil",
"Type_Boolean",
"Type_Number",
"Type_String",
]
COMPILER_TYPES_MAPPING = {k:v for k, v in enumerate(COMPILER_TYPES)}
MERGE (COMPILER_TYPES_MAPPING, {v:k for k, v in enumerate(COMPILER_TYPES)})

BASE_DIR = "E:/dumps/2023-04-28/"
BINS_DIR = os.path.join(BASE_DIR, 'bins')
MEMS_DIR = os.path.join(BASE_DIR, 'mem')
SEARCHES_DIR = os.path.join(BASE_DIR, 'searches')
DUMP_EXT = 'DMP'

DUMP_FMT = "{base_dir}/{bin_name}.{dmp_ext}"
LUAPAGE_POINTER_FMT = "{base_dir}/{bin_name}/luapage_comments.json"
POINTERS_FMT = "{base_dir}/{bin_name}/pointer_comments.json"
MEMORY_INFO_FMT = "{base_dir}/{bin_name}.json"

IDENTIFIED_OBJECTS_PARSE_FMT = "{base_dir}/{bin_name}/memory_ranges_roblox_assets.json"
IDENTIFIED_OBJECTS_FULL_FMT = "{base_dir}/{bin_name}/full_dump_roblox_assets.json"

SAVED_OBJECTS_FILE = "{base_dir}/{bin_name}/gcos_and_structs.json"
FULL_EXTRACTED_GAME_ASSETS_BASE = "{base_dir}/{bin_name}/extracted_assets/full/"
PARSE_EXTRACTED_GAME_ASSETS_BASE = "{base_dir}/{bin_name}/extracted_assets/parse/"

def reset_global_deps(base_dir):
    global BASE_DIR, BINS_DIR, MEMS_DIR, SEARCHES_DIR
    BASE_DIR = base_dir
    BINS_DIR = os.path.join(BASE_DIR, 'bins')
    MEMS_DIR = os.path.join(BASE_DIR, 'mem')
    SEARCHES_DIR = os.path.join(BASE_DIR, 'searches')


