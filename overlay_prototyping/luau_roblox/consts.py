CTYPE_VALUE_FMTS = {
    'b': "{:02x}", 'B': "{:02x}", "?": "{:02x}",
    'h': "{:04x}", 'H': "{:04x}",
    'i': "{:08x}", 'I': "{:08x}", 'l': "{:08x}", 'L': "{:08x}",
    'q': "{:08x}", 'Q': "{:08x}",
    'e': "{:f}", 'f': "{:f}", 'd': "{:f}",
}

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
    TFUNCTION: "function",
    TCLOSURE: "closure",
    TUSERDATA: "userdata",
    TTHREAD: "thread",
    TPROTO: "proto",
    TUPVAL: "upval",
}

LUAR_ROBLOX_TAG_TYPES = {
    TNIL: "nil",
    TBOOLEAN: "boolean",
    TLIGHTUSERDATA: "userdata",
    TNUMBER: "number",
    TVECTOR: "vector",
    TSTRING: "string",
    TTABLE: "table",
    TCLOSURE: "function",
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
