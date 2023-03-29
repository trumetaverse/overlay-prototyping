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

LUAR_ROBLOX_TYPES = {
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
