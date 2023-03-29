from ctypes import *

VALID_MARKS = {0, 1, 2, 4, 8, 9, 0xf}

TNIL = 0
TBOOLEAN = 1
TLIGHTUSERDATA = 2
TNUMBER = 3
TVECTOR = 4
TSTRING = 5
TTABLE = 6
TFUNCTION = 7
TUSERDATA = 8
TTHREAD = 9
TPROTO = 0xA
TUPVAL = 0xB
TDEADKEY = 0xC

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

LUAUR_GCHEADER = [
    ['B', 'B', 'uint8_t', 'tt'],
    ['B', 'B', 'uint8_t', 'marked'],
    ['B', 'B', 'uint8_t', 'memcat'],
    ['B', 'B', 'uint8_t', 'gc_padding_0'],
]

LUAUR_USERDATA = LUAUR_GCHEADER + \
                 [
                     ['B', 'B', 'uint8_t', 'tag'],
                     ['3B', '3B', 'uint8_t', 'padding_0'],
                     ['I', 'I', 'uint32_t', 'len'],
                     ['I', 'I', 'Table*', 'metatable'],
                     ['B', 'B', 'uint8_t', 'gc_padding_0'],
                 ]

LUAR_VALUE = [
    ['I', 'I', 'uint32_t', 'raw_value_0'],
    ['I', 'I', 'uint32_t', 'raw_value_1'],
    ['I', 'I', 'uint32_t', 'raw_value_2'],
]

LUAR_TVALUE = [
    ['I', 'I', 'uint32_t', 'raw_value_0'],
    ['I', 'I', 'uint32_t', 'raw_value_1'],
    ['I', 'I', 'uint32_t', 'raw_value_2'],
    ['I', 'I', 'uint32_t', 'tt'],
]

LUAR_TVALUE_FLOAT = [
    ['f', 'f', 'float', 'x'],
    ['f', 'f', 'float', 'y'],
    ['f', 'f', 'float', 'z'],
    ['I', 'I', 'uint32_t', 'tt'],
]

LUAR_TVALUE_DOUBLE = [
    ['d', 'd', 'double', 'n'],
    ['I', 'I', 'void*', 'padding_0'],
    ['I', 'I', 'uint32_t', 'tt'],
]

LUAR_TVALUE_BOOL = [
    ['I', 'I', 'uint32_t', 'b'],
    ['I', 'I', 'void*', 'padding_0'],
    ['I', 'I', 'void*', 'padding_1'],
    ['I', 'I', 'uint32_t', 'tt'],
]

LUAR_TVALUE_GCOBJECT = [
    ['I', 'I', 'GCObject*', 'gc'],
    ['I', 'I', 'void*', 'padding_0'],
    ['I', 'I', 'void*', 'padding_1'],
    ['I', 'I', 'uint32_t', 'tt'],
]

LUAR_TVALUE_DATA = [
    ['I', 'I', 'void*', 'p'],
    ['I', 'I', 'void*', 'padding_0'],
    ['I', 'I', 'void*', 'padding_1'],
    ['I', 'I', 'uint32_t', 'tt'],
]

LUAR_TVALUE_INT = [
    ['I', 'I', 'uint32_t', 'b'],
    ['I', 'I', 'void*', 'padding_0'],
    ['I', 'I', 'void*', 'padding_1'],
    ['I', 'I', 'uint32_t', 'tt'],
]

LUAR_VALUE_DOUBLE = [
    ['d', 'd', 'double', 'n'],
]

LUAR_VALUE_FLOAT = [
    ['2f', '2f', 'float[2]', 'v'],
]

LUAUR_TSTRING = LUAUR_GCHEADER + \
                [
                    ['H', 'H', 'uint16_t', 'atom'],
                    ['H', 'H', 'uint16_t', 'ts_padding_0'],
                    ['I', 'I', 'TString*', 'next'],
                    ['I', 'I', 'uint32_t', 'hash'],
                    ['I', 'I', 'uint8_t*', 'end'],
                    # need to set the data field manually
                    # ['I', 'I', 'char*', 'data'],
                ]

LUAUR_UPVAL_OPEN = LUAUR_GCHEADER + \
                   [
                       ['B', 'B', 'uint8_t', 'markedopen'],
                       ['3B', '3B', 'uint8_t', 'padding_0'],
                       ['I', 'I', 'TValue*', 'v'],
                       # Union close
                       ['I', 'I', 'TValue*', 'prev'],
                       ['I', 'I', 'TValue*', 'next'],
                       ['I', 'I', 'TValue*', 'threadnext'],

                   ]

LUAUR_UPVAL_CLOSE = LUAUR_GCHEADER + \
                    [
                        ['B', 'B', 'uint8_t', 'markedopen'],
                        ['3B', '3B', 'uint8_t', 'padding_0'],
                        ['I', 'I', 'TValue*', 'v'],
                        # Union open
                        ['I', 'I', 'TValue*', 'prev'],
                        ['I', 'I', 'TValue*', 'next'],
                        ['I', 'I', 'TValue*', 'threadnext'],

                    ]

LUAUR_LOCVAR = [
    ['I', 'I', 'TSstring*', 'varname'],
    ['I', 'I', 'uint32_t', 'startpc'],
    ['I', 'I', 'uint32_t', 'endpc'],
    ['B', 'B', 'uint8_t', 'reg'],
    ['3B', '3B', 'uint8_t[]', 'padding'],
]

LUAR_PROTO_CE = LUAUR_GCHEADER + \
                [
                    ['I', 'I', 'TValue*', 'k'],
                    ['I', 'I', 'Instruction*', 'code'],
                    ['I', 'I', 'Proto**', 'p'],
                    ['I', 'I', 'uint8_t*', 'lineinfo'],
                    ['I', 'I', 'int32_t*', 'abslineinfo'],
                    ['I', 'I', 'struct LocVar*', 'locvars'],
                    ['I', 'I', 'TString**', 'upvalues'],
                    ['I', 'I', 'TString*', 'source'],
                    ['I', 'I', 'TString*', 'debugname'],
                    ['I', 'I', 'uint8_t*', 'debuginsn'],
                    ['I', 'I', 'void*', 'execdata'],
                    ['I', 'I', 'GCObject*', 'gclist'],
                    ["I", "I", "uint32_t", "sizecode"],
                    ["I", "I", "uint32_t", "sizep"],
                    ["I", "I", "uint32_t", "sizelocvars"],
                    ["I", "I", "uint32_t", "sizeupvalues"],
                    ["I", "I", "uint32_t", "sizek"],
                    ["I", "I", "uint32_t", "sizelineinfo"],
                    ["I", "I", "uint32_t", "linegaplog2"],
                    ["I", "I", "uint32_t", "linedefined"],
                    ["I", "I", "uint32_t", "bytecodeid"],
                    ["I", "I", "uint8_t", "nups"],
                    ["I", "I", "uint8_t", "numparams"],
                    ["I", "I", "uint8_t", "is_vararg"],
                    ["I", "I", "uint8_t", "maxstacksize"],
                ]

LUAR_PROTO = LUAUR_GCHEADER + \
             [
                 ['I', 'I', 'TValue*', 'k'],
                 ['I', 'I', 'Instruction*', 'code'],
                 ['I', 'I', 'Proto**', 'p'],
                 ['I', 'I', 'uint8_t*', 'lineinfo'],
                 ['I', 'I', 'int32_t*', 'abslineinfo'],
                 ['I', 'I', 'struct LocVar*', 'locvars'],
                 ['I', 'I', 'TString**', 'upvalues'],
                 ['I', 'I', 'TString*', 'source'],
                 ['I', 'I', 'TString*', 'debugname'],
                 ['I', 'I', 'uint8_t*', 'debuginsn'],
                 ['I', 'I', 'void*', 'execdata'],
                 ['I', 'I', 'GCObject*', 'gclist'],
                 ["I", "I", "uint32_t", "sizecode"],
                 ["I", "I", "uint32_t", "sizep"],
                 ["I", "I", "uint32_t", "sizelocvars"],
                 ["I", "I", "uint32_t", "sizeupvalues"],
                 ["I", "I", "uint32_t", "sizek"],
                 ["I", "I", "uint32_t", "sizelineinfo"],
                 ["I", "I", "uint32_t", "linegaplog2"],
                 ["I", "I", "uint32_t", "linedefined"],
                 ["I", "I", "uint32_t", "bytecodeid"],
                 ["I", "I", "uint8_t", "nups"],
                 ["I", "I", "uint8_t", "numparams"],
                 ["I", "I", "uint8_t", "is_vararg"],
                 ["I", "I", "uint8_t", "maxstacksize"],
             ]

LUAR_TKEY = LUAR_VALUE + [
    ['I', 'I', 'unsigned32_t', 'extra'],
    ['I', 'I', 'unsigned32_t', 'tt_next'],
]

LUAR_NODE = [['I', 'I', 'uint32_t', 'raw_value_0'],
             ['I', 'I', 'uint32_t', 'raw_value_1'],
             ['I', 'I', 'uint32_t', 'raw_value_2'],
             ['I', 'I', 'uint32_t', 'tt'], ] \
            + LUAR_TKEY

LUAR_CLOSURE_UVALS = LUAUR_GCHEADER + \
                     [
                         ['B', 'B', 'uint8_t', 'isC'],
                         ['B', 'B', 'uint8_t', 'nupvalues'],
                         ['B', 'B', 'uint8_t', 'stacksize'],
                         ['B', 'B', 'uint8_t', 'preload'],
                         ['I', 'I', 'GCObject*', 'gclist'],
                         ['I', 'I', 'struct Table*', 'env'],

                         ['I', 'I', '(*lua_CFunction)', 'f'],
                         ['I', 'I', '(*lua_Continuation)', 'cont'],
                         ['I', 'I', 'const char*', 'debugname'],
                         ['3I', '3I', 'TValue', 'upvals'],
                     ]
LUAR_CLOSURE_RAW = LUAUR_GCHEADER + \
                     [
                         ['B', 'B', 'uint8_t', 'isC'],
                         ['B', 'B', 'uint8_t', 'nupvalues'],
                         ['B', 'B', 'uint8_t', 'stacksize'],
                         ['B', 'B', 'uint8_t', 'preload'],
                         ['I', 'I', 'GCObject*', 'gclist'],
                         ['I', 'I', 'struct Table*', 'env'],

                         ['I', 'I', 'void*', 'raw_value_0'],
                         ['I', 'I', 'void*', 'raw_value_2'],
                         ['I', 'I', 'void*', 'raw_value_3'],
                         ['I', 'I', 'void*', 'raw_value_4'],
                         ['I', 'I', 'void*', 'raw_value_5'],
                         ['I', 'I', 'void*', 'raw_value_6'],

                     ]

LUAR_CLOSURE_UPREFS = LUAUR_GCHEADER + \
                      [
                          ['B', 'B', 'uint8_t', 'isC'],
                          ['B', 'B', 'uint8_t', 'nupvalues'],
                          ['B', 'B', 'uint8_t', 'stacksize'],
                          ['B', 'B', 'uint8_t', 'preload'],
                          ['I', 'I', 'GCObject*', 'gclist'],
                          ['I', 'I', 'struct Table*', 'env'],

                          ['I', 'I', '(*lua_CFunction)', 'f'],
                          ['I', 'I', '(*lua_Continuation)', 'cont'],
                          ['I', 'I', 'const char*', 'debugname'],
                          ['3I', '3I', 'TValue', 'uprefs'],
                      ]

LUAR_TABLE = LUAUR_GCHEADER + \
             [
                 ['B', 'B', 'uint8_t', 'tmcache'],
                 ['B', 'B', 'uint8_t', 'readonly'],
                 ['B', 'B', 'uint8_t', 'safeenv'],
                 ['B', 'B', 'uint8_t', 'lsizenode'],
                 ['B', 'B', 'uint8_t', 'nodemask8'],
                 ['B', 'B', 'uint8_t', 'padding_0'],
                 ['B', 'B', 'uint8_t', 'padding_1'],
                 ['B', 'B', 'uint8_t', 'padding_2'],
                 ['I', 'I', 'uint32_t', 'sizearray'],
                 ['I', 'I', 'uint32_t', 'lastfree_aboundary'],
                 ['I', 'I', 'Table*', 'metatable'],
                 ['I', 'I', 'LuaValue*', 'array'],
                 ['I', 'I', 'LuaNode*', 'node'],
                 ['I', 'I', 'GCObject*', 'gclist'],
             ]

LUAR_STATE = LUAUR_GCHEADER + [
    ['B', 'B', 'uint8_t', 'status'],
    ['B', 'B', 'uint8_t', 'activememcat'],
    ['B', 'B', 'uint8_t', 'isactive'],
    ['B', 'B', 'uint8_t', 'singlestep'],

    ['I', 'I', 'TValue*', 'top'],
    ['I', 'I', 'TValue*', 'base'],
    ['I', 'I', 'globlal_State*', 'global'],
    ['I', 'I', 'CallInfo*', 'ci'],
    ['I', 'I', 'TValue*', 'stack_last'],
    ['I', 'I', 'TValue*', 'stack'],
    ['I', 'I', 'CallInfo*', 'end_ci'],
    ['I', 'I', 'CallInfo*', 'base_ci'],
    ['I', 'I', 'int', 'stacksize'],
    ['I', 'I', 'int', 'size_ci'],
    ['I', 'I', 'uint16_t', 'nCcalls'],
    ['I', 'I', 'uint16_t', 'baseCcalls'],
    ['I', 'I', 'uint32_t', 'cachedslot'],
    ['I', 'I', 'Table*', 'gt'],
    ['I', 'I', 'UpVal*', 'openupval'],
    ['I', 'I', 'GCObject*', 'gclist'],
    ['I', 'I', 'TString*', 'namecall'],
    ['I', 'I', 'void*', 'userdata'],
]

LUAR_DEBUG = [
    ['I', 'Q', 'const char*', 'name'],
    ['I', 'Q', 'const char*', 'what'],
    ['I', 'Q', 'const char*', 'source'],
    ['I', 'Q', 'const char*', 'short_src'],

    ['I', 'I', 'int', 'linedefined'],
    ['I', 'I', 'int', 'currentline'],

    ['B', 'B', 'uint8_t', 'nupvals'],
    ['B', 'B', 'uint8_t', 'nparams'],
    ['B', 'B', 'uint8_t', 'isvaarg'],
    ['B', 'B', 'uint8_t', 'padding_0'],

    ['I', 'Q', 'void*', 'userdata'],
    ['256B', '256B', 'uint8_t*', 'ssbuf'],


]

LUAR_CALLBACKS = [
    ['I', 'Q', 'void*', 'userdata'],
    ['I', 'Q', 'fn *interrupt', 'interrupt'],
    ['I', 'Q', 'fn *panic', 'panic'],
    ['I', 'Q', 'fn *userthread', 'userthread'],

    ['I', 'Q', 'fn *useratom', 'useratom'],
    ['I', 'Q', 'fn *debugbreak', 'debugbreak'],
    ['I', 'Q', 'fn *debugstep', 'debugstep'],
    ['I', 'Q', 'fn *debuginterrupt', 'debuginterrupt'],
    ['I', 'Q', 'panic*', 'debugprotectederror'],


]

LUAR_EXECUTION_CALLBACKS = [
    ['I', 'Q', 'void*', 'context'],
['I', 'Q', 'fn *', 'close'],
['I', 'Q', 'fn *', 'destroy'],
['I', 'Q', 'fn *', 'enter'],
['I', 'Q', 'fn *', 'setbreakpoint'],
]

LUAR_GLOBAL_STATE = [
    ['I', 'Q', 'void*', 'strt'],
['I', 'Q', 'void*', 'ud'],
['B', 'B', 'uint8_t', 'currentwhite'],
['B', 'B', 'uint8_t', 'gcstate'],
['B', 'B', 'uint8_t', 'padding_0'],
['B', 'B', 'uint8_t', 'padding_1'],
['I', 'Q', 'GCObject*', 'gray'],
['I', 'Q', 'GCObject*', 'grayagain'],
['I', 'Q', 'GCObject*', 'weak'],

['I', 'Q', 'size_t', 'GCthreshold'],
['I', 'Q', 'size_t', 'totalbytes'],

['I', 'Q', 'size_t', 'gcgoal'],
['I', 'Q', 'size_t', 'gcstepmul'],
['I', 'Q', 'size_t', 'gcstepsize'],

['I', 'Q', 'size_t', 'gcgoal'],
['I', 'Q', 'size_t', 'gcstepmul'],
['I', 'Q', 'size_t', 'gcstepsize'],

['32I', '32Q', 'struct lua_Page*', 'freepages'],
['32I', '32Q', 'struct lua_Page*', 'freegcopages'],
['I', 'Q', 'struct lua_Page*', 'allgcopages'],
['I', 'Q', 'struct lua_Page*', 'sweepgcopage'],
['256I', '256I', 'size_t', 'memcatbytes'],
['I', 'Q', 'lua_State*', 'mainthread'],] + \
                    LUAUR_UPVAL_CLOSE  + \
    [
    ['10I', '10Q', 'Table*', 'mt[LUA_T_COUNT]'],
    ['10I', '10Q', 'TString*', 'ttname[LUA_T_COUNT]'],
    ['21I', '21Q', 'TString*', 'tmname[21]'],

    ] + \
    [
['I', 'I', 'uint32_t', 'pseudotemp_raw_value_0'],
['I', 'I', 'uint32_t', 'pseudotemp_raw_value_1'],
['I', 'I', 'uint32_t', 'pseudotemp_raw_value_2'],
['I', 'I', 'uint32_t', 'pseudotemp_tt'],
    ] + \
    [
['I', 'I', 'uint32_t', 'registry_raw_value_0'],
['I', 'I', 'uint32_t', 'registry_raw_value_1'],
['I', 'I', 'uint32_t', 'registry_raw_value_2'],
['I', 'I', 'uint32_t', 'registry_tt'],
                    ] + \
    [
['I', 'I', 'uint32_t', 'registryfree'],
['I', 'I', 'struct lua_jmpbuf*', 'errorjmp'],
['Q', 'Q', 'uint64_t', 'rngstate'],
['4Q', '4Q', 'uint64_t', 'ptrenckey'],
['I', 'I', 'struct lua_jmpbuf*', 'errorjmp'],
['128I', '128Q', 'fn *udatagc', '*udatagc[LUA_UTAG_LIMIT]'],
        ] + \
    [
                        ['I', 'Q', 'void*', 'cb_userdata'],
                        ['I', 'Q', 'fn *interrupt', 'cb_interrupt'],
                        ['I', 'Q', 'fn *panic', 'cb_panic'],
                        ['I', 'Q', 'fn *userthread', 'cb_userthread'],
                        ['I', 'Q', 'fn *useratom', 'cb_useratom'],
                        ['I', 'Q', 'fn *debugbreak', 'cb_debugbreak'],
                        ['I', 'Q', 'fn *debugstep', 'cb_debugstep'],
                        ['I', 'Q', 'fn *debuginterrupt', 'cb_debuginterrupt'],
                        ['I', 'Q', 'panic*', 'cb_debugprotectederror'],

                    ] + \
    [
                        ['I', 'Q', 'void*', 'ecb_context'],
                        ['I', 'Q', 'fn *', 'ecb_close'],
                        ['I', 'Q', 'fn *', 'ecb_destroy'],
                        ['I', 'Q', 'fn *', 'ecb_enter'],
                        ['I', 'Q', 'fn *', 'ecb_setbreakpoint'],
                    ] + \
    [
                        ['32I', '32I', 'int32_t', 'gcstats_triggerterms'],
                        ['I', 'I', 'int32_t', 'gcstats_triggertermpos'],
                        ['I', 'I', 'int32_t', 'gcstats_triggerintegral'],

['I', 'I', 'int32_t', 'gcstats_atomicstarttotalsizebytes'],
['I', 'I', 'int32_t', 'gcstats_endtotalsizebytes'],
['I', 'I', 'int32_t', 'gcstats_heapgoalsizebytes'],

['d', 'd', 'double', 'gcstats_atomicstarttotalsizebytes'],
['d', 'd', 'double', 'gcstats_atomicstarttimestamp'],
['d', 'd', 'double', 'gcstats_endtimestamp'],
                    ]
