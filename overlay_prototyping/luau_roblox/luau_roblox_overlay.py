from ctypes import *

VALID_MARKS = {0, 1, 2, 4, 8, 9, 0xf}

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