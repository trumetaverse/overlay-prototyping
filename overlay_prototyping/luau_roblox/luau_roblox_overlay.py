from ctypes import *

LUAUR_GCHeader = [
    ['B', 'B', 'uint8_t', 'tt'],
    ['B', 'B', 'uint8_t', 'marked'],
    ['B', 'B', 'uint8_t', 'memcat'],
    ['B', 'B', 'uint8_t', 'gc_padding_0'],
]

LUAUR_TSTRING = LUAUR_GCHeader + \
    [
        ['H', 'H', 'uint16_t', 'atom'],
        ['H', 'H', 'uint16_t', 'ts_padding_0'],
        ['I', 'I', 'TString*', 'next'],
        ['I', 'I', 'uint32_t', 'hash'],
        ['I', 'I', 'uint8_t*', 'end'],
        # need to set the data field manually
        # ['I', 'I', 'char*', 'data'],

    ]