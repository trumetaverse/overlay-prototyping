import ctypes
import struct
from ctypes import *

from .consts import *
from ..base import BaseException

from .. transmute.base_le_structs import Transmute_BaseLES
from .. transmute.base_le_union import Transmute_BaseLEU



class LuauRW_GCHeader(Transmute_BaseLES):
    _gco_ = True
    _has_sanity_check_ = True
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},
    }
    _fields_ = Transmute_BaseLES.create_fields(__field_def__)
    _fields_dict_ = Transmute_BaseLES.create_fields_dict(__field_def__)

    def __init__(self, **kargs):
        super(LuauRW_GCHeader, self).__init__(**kargs)

    def is_valid_gc_header(self):
        if not self.has_gc_header():
            return False

        fld = self.get_gch()
        if fld is None:
            return False
        valid_gch = fld.tt in TYPES and fld.marked in VALID_MARKS
        ett = self.expected_tt
        # constraining the validity to the object type (if known) and gch headers
        if valid_gch and ett is None:
            return True
        elif valid_gch and ett == fld.tt:
            return True
        return False

    def sanity_check(self):
        return self.tt in VALID_OBJ_TYPES and self.mark in VALID_MARKS and self.gch_padding == 0

class LuauRW_BaseStruct(Transmute_BaseLES):
    _OVERLAY_TYPE_ = 'LuauRW'
    _fields_ = []
    _fields_dict_ = {}
    _is_union_ = False
    _field_fixups_ = {}
    _gco_ = False
    _tt_ = None
    _init_required_ = True
    _gc_header_cls_ = LuauRW_GCHeader

    @classmethod
    def create_fields(cls, json_fields):
        return [(k, eval(v['type']), v['bits']) if 'bits' in v else (k, eval(v['type'])) for k, v in
                json_fields.items()]

    @classmethod
    def create_fields_dict(cls, json_fields):
        return dict((k, eval(v['type'])) if 'bits' in v else (k, eval(v['type'])) for k, v in
                    json_fields.items())
    def __init__(self, **kargs):
        super(LuauRW_BaseStruct, self).__init__(**kargs)
        # buf = kargs.get('buf', None)
        # if isinstance(buf, bytes):
        #     fit = min(len(buf), sizeof(self))
        #     memmove(addressof(self), buf, fit)
        # self.initialize_with_kargs(**kargs)

    @property
    def expected_tt(self):
        return None

    def get_gch(self):
        fld = None
        if not self._gco_ or self._gc_header_cls_ is None:
            return None
        if hasattr(self, '_cached_gch'):
            return getattr(self, '_cached_gch')
        elif hasattr(self, 'tt') and hasattr(self, 'marked') and hasattr(self, 'gch_padding'):
            fld = self
        elif self.__class__.__name__.find('LuauRW_GCHeader') > -1:
            fld = self
        else:
            for x in self._fields_:
                name, fld = x[:2]
                if fld_type.__name__.find('LuauRW_GCHeader') > -1:
                    fld = getattr(self, name)
                    break
        setattr(self, '_cached_gch', fld)
        return fld

    def is_valid_gc_header(self):
        if not self.has_gc_header():
            return False

        fld = self.get_gch()
        if fld is None:
            return False
        valid_gch = fld.tt in TYPES and fld.marked in VALID_MARKS
        ett = self.expected_tt
        # constraining the validity to the object type (if known) and gch headers
        if valid_gch and ett is None:
            return True
        elif valid_gch and ett == fld.tt:
            return True
        return False

    @property
    def expected_tt(self):
        return self._tt_

    def valid_type(self, type_enum):
        fld = self.get_gch()
        return fld is not None and fld.tt == type_enum and fld.marked in VALID_MARKS

    def is_string(self):
        return self.valid_type(TSTRING)

    def is_bool(self):
        return self.valid_type(TBOOLEAN)

    def is_table(self):
        return self.valid_type(TTABLE)

    def is_ud(self):
        return self.valid_type(TUSERDATA)

    def is_function(self):
        return self.valid_type(TFUNCTION)

    def is_number(self):
        return self.valid_type(TNUMBER)

    def is_vector(self):
        return self.valid_type(TVECTOR)

    def is_thread(self):
        return self.valid_type(TTHREAD)

    def is_proto(self):
        return self.valid_type(TPROTO)

    def is_upval(self):
        return self.valid_type(TUPVAL)

    def is_lud(self):
        return self.valid_type(TLIGHTUSERDATA)

    def is_prim(self):
        fld = self.get_gch()
        return fld is not None and fld.tt in {TNUMBER, TBOOLEAN, TVECTOR, TNIL}

    @classmethod
    def lua_hash_string(cls, value):
        a = 0
        b = 0
        length = len(value)
        h = len(value)

        while length >= 32:
            block = struct.unpack("III", value[:12])
            a += block[0]
            b += block[1]
            h += block[2]
            u = 14
            v = 11
            w = 25
            a ^= h
            a -= ((h << u) | (h >> (32 - u)))
            b ^= a
            b -= ((a << v) | (a >> (32 - v)))
            h ^= b
            h -= ((b << w) | (b >> (32 - w)))
            value = value[12:]
            length -= 12

        for i in range(length):
            h ^= ((h << 5) + (h >> 2) + ord(value[i]))

        b = struct.pack('>Q', h)
        h = struct.unpack('>I', b[-4:])[0]
        return h

    def lua_hash_value(self):
        return None


class LuauRW_BaseUnion(Transmute_BaseLEU):
    _OVERLAY_TYPE_ = 'LuauRW'
    _fields_ = []
    _fields_dict_ = {}
    _is_union_ = True
    _field_fixups_ = {}
    _gco_ = False
    _tt_ = None
    _init_required_ = True
    _gc_header_cls_ = LuauRW_GCHeader

    def __init__(self, **kargs):
        super(LuauRW_BaseUnion, self).__init__(**kargs)
        # buf = kargs.get('buf', None)
        # if isinstance(buf, bytes):
        #     fit = min(len(buf), sizeof(self))
        #     memmove(addressof(self), buf, fit)
        #     # for name, fld_type in self._fields_:
        #     #     fld = getattr(self, name)
        #     #     fit = min(len(buf), sizeof(fld))
        #     #     memmove(addressof(fld), buf, fit)
        #
        # self.initialize_with_kargs(**kargs)


    def get_gch(self):
        fld = None
        if not self._gco_ or self._gc_header_cls_ is None:
            return None
        if hasattr(self, '_cached_gch'):
            return getattr(self, '_cached_gch')
        elif hasattr(self, 'tt') and hasattr(self, 'marked') and hasattr(self, 'gch_padding'):
            fld = self
        elif self.__class__.__name__.find('LuauRW_GCHeader') > -1:
            fld = self
        else:
            for x in self._fields_:
                name, fld_type = x[:2]
                if fld_type.__name__.find('LuauRW_GCHeader') > -1:
                    fld = getattr(self, name)
                    break
        setattr(self, '_cached_gch', fld)
        return fld

    @property
    def expected_tt(self):
        return self._tt_

    def is_valid_gc_header(self):
        fld = self.get_gch()
        if fld is None:
            return False
        return fld.tt in VALID_OBJ_TYPES and fld.marked in VALID_MARKS

    def valid_type(self, type_enum):
        fld = self.get_gch()
        return fld is not None and fld.tt == type_enum and fld.marked in VALID_MARKS

    def is_string(self):
        return self.valid_type(TSTRING)

    def is_bool(self):
        return self.valid_type(TBOOLEAN)

    def is_table(self):
        return self.valid_type(TTABLE)

    def is_ud(self):
        return self.valid_type(TUSERDATA)

    def is_function(self):
        return self.valid_type(TFUNCTION)

    def is_number(self):
        return self.valid_type(TNUMBER)

    def is_vector(self):
        return self.valid_type(TVECTOR)

    def is_thread(self):
        return self.valid_type(TTHREAD)

    def is_proto(self):
        return self.valid_type(TPROTO)

    def is_upval(self):
        return self.valid_type(TUPVAL)

    def is_lud(self):
        return self.valid_type(TLIGHTUSERDATA)

    def is_prim(self):
        fld = self.get_gch()
        return fld is not None and fld.tt in {TNUMBER, TBOOLEAN, TVECTOR, TNIL}



class LuauRW_TString(LuauRW_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TSTRING
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},
        "atom": {"type": "c_uint16"},
        "next": {"type": "c_uint32"},
        "hash": {"type": "c_uint32"},
        "end": {"type": "c_uint32"},
        # "data": {"type": "c_char"},
    }
    _field_fixups_ = {
        "metatable": "Table*",
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)

    def has_data(self):
        return self.has_value()

    def has_value(self):
        return getattr(self, '__value', None) is not None

    def get_value_offset(self):
        return getattr(self, '__value_offset', None)

    @classmethod
    def deserialize(cls, addr, nbytes, analysis=None, word_sz=4):
        f = cls(addr=addr, analysis=analysis, buf=nbytes, word_sz=word_sz)
        return f

    def get_dump(self, word_sz=None, addr=0):
        r, flat = super(LuauRW_TString, self).get_dump( word_sz=None)

        addr = self.addr if self.addr is not None and self.addr > 0 else addr
        # addr = getattr(self, 'addr') if hasattr(self, 'addr') else 0
        vo = self.get_value_offset()
        addr = addr + vo if vo is not None else addr
        v = self.get_value()
        if v is not None:
            x = {"name": "data", "value":v[:80], "addr": addr, 'type': 'char[]', 'offset': vo,
                 "fmt": "{}", "is_array": False}
            r[x['addr']] = x
            flat.append(x)
        else:
            x = {"name": "data", "value": None, "addr": addr, 'type': None, 'offset': vo,
                 "fmt": "{}", "is_array": False}
        return r, flat

    def sanity_check(self):
        return self.is_valid_gc_header()

    def do_fixups(self, **kargs):
        sz = sizeof(self)
        str_len = self.end - (self.addr + sz) + self.word_sz
        # if str_len % self.word_sz == 0:
        #     str_len += self.word_sz
        buf = kargs.get('buf', None)
        setattr(self, 'data', None)
        analysis = getattr(self, 'analysis', None)
        value = None
        if analysis is not None and str_len > 0:
            data = analysis.read_vaddr(self.addr+sz, str_len)
            value = "".join([chr(x) for x in data])
        elif buf and len(buf) > sz:
            value = "".join([chr(x) for x in buf[sz:sz + str_len]])

        str_buf_len = str_len
        if str_len % self.word_sz != 0:
            str_buf_len = str_len + self.word_sz - (str_len % self.word_sz)

        setattr(self, 'data', value)
        setattr(self, '__value', value)
        setattr(self, '__str_buf_len', str_buf_len)
        setattr(self, '__value_offset', sz)

    @property
    def str_buf_len(self):
        return getattr(self, '__str_buf_len', 0)

    def get_total_size(self):
        value = self.get_value()
        if value is None or len(value) == 0:
            return sizeof(self)
        return sizeof(self) + self.str_buf_len

    def get_next_gco(self):
        value = self.get_value()
        if value is None or len(value) == 0:
            return sizeof(self)

        sz = sizeof(self) + self.str_buf_len
        if sz % 8 != 0:
            sz = sz + 8 - (sz % 8)
        return sz + self.addr

    def lua_hash_value(self):
        value = self.get_value()
        if value is not None:
            return self.lua_hash_string(value)
        return None


class LuauRW_ForceAlignment(LuauRW_BaseUnion):
    _OVERLAY_TYPE_ = 'LuauRW'
    __field_def__ = {
        "data": {"type": "c_uint8*1"},
        "align1": {"type": "c_double"},
        # "align2": {"type": "c_void_p"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_Value(LuauRW_BaseUnion):
    _OVERLAY_TYPE_ = 'LuauRW'
    __field_def__ = {
        "gc": {"type": "c_uint32"},
        "p": {"type": "c_uint32"},
        "n": {"type": "c_double"},
        "b": {"type": "c_int32"},
        "v": {"type": "c_float"},
    }
    _field_fixups_ = {"gc": "GCObject*", "p": "void*"}
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_TValue(LuauRW_BaseStruct):
    _OVERLAY_TYPE_ = 'LuauRW'
    __field_def__ = {
        "value": {"type": "LuauRW_Value"},
        "extra": {"type": "c_uint32*1"},
        "tt": {"type": "c_uint32"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_TableArrayBoundary(LuauRW_BaseUnion):
    __field_def__ = {
        "lastfree": {"type": "c_uint32"},
        "aboundary": {"type": "c_uint32"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_Table(LuauRW_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TTABLE
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},

        "tmcache": {"type": "c_uint8"},
        "readonly": {"type": "c_uint8"},
        "safeenv": {"type": "c_uint8"},
        "lsizenode": {"type": "c_uint8"},
        "nodemask8": {"type": "c_uint8"},
        "sizearray": {"type": "c_uint32"},
        # "lastfree_aboundary": {"type": "c_uint32"},
        #  Original
        # "__anonymous__": {"type": "LuauRW_BaseUnionArrayBoundary"},
        # "metatable": {"type": "c_uint32"},  # Table*
        #  Swapped after some analysis
        "metatable": {"type": "c_uint32"},  # Table*
        "__anonymous__": {"type": "LuauRW_TableArrayBoundary"},
        "array": {"type": "c_uint32"},
        "node": {"type": "c_uint32"},
        "gclist": {"type": "c_uint32"},
    }
    _field_fixups_ = {
        "metatable": "Table*",
        "array": "TValue*",
        "node": "LuaNode*",
        "gclist": "GCObject*"
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()

    def get_next_gco(self):
        return self.addr + self.get_total_size()-self.word_sz

    def get_tvalue_address(self, index):
        return self.addr + self.get_offset('array') + index * ctypes.sizeof(LuauRW_TValue)

class LuauRW_LocVar(LuauRW_BaseStruct):
    __field_def__ = {
        "varname": {"type": "c_uint32"},  # TString*
        "startpc": {"type": "c_uint8"},
        "endpc": {"type": "c_uint8"},
        "reg": {"type": "c_uint8"},
    }
    _field_fixups_ = {"varname": "TString*"}
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_Udata(LuauRW_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TUSERDATA
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},
        "tag": {"type": "c_uint8"},
        "len": {"type": "c_int32"},
        "metatable": {"type": "c_uint32"},
        "data": {"type": "LuauRW_ForceAlignment"},
    }
    _field_fixups_ = {
        "metatable": "Table*",
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()

    def get_next_gco(self):
        return self.addr + self.get_total_size()


class LuauRW_UpValOpenUnion(LuauRW_BaseUnion):
    __field_def__ = {
        "prev": {"type": "c_uint32"},
        "next": {"type": "c_uint32"},
        "thread": {"type": "c_uint32"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "prev": "UpVal*",
        "next": "UpVal*",
        "thread": "UpVal*",
    }


class LuauRW_UpValUnion(LuauRW_BaseUnion):
    __field_def__ = {
        "value": {"type": "LuauRW_TValue"},
        "open": {"type": "LuauRW_UpValOpenUnion"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_UpVal(LuauRW_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TUPVAL
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},

        "markedopen": {"type": "c_int8"},
        "v": {"type": "c_uint32"},

        "u": {"type": "LuauRW_UpValUnion"},
        "metatable": {"type": "c_uint32"},
        "data": {"type": "c_uint8*8"},
    }
    _field_fixups_ = {
        "v": "TValue*",
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()

    def get_next_gco(self):
        return self.addr + self.get_total_size()

class LuauRW_Proto(LuauRW_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TPROTO
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},

        "k": {"type": "c_uint32"},
        "code": {"type": "c_uint32"},
        "p": {"type": "c_uint32"},
        "lineinfo": {"type": "c_uint32"},
        "abslineinfo": {"type": "c_uint32"},
        "locvars": {"type": "c_uint32"},
        "upvalues": {"type": "c_uint32"},
        "source": {"type": "c_uint32"},
        "debugname": {"type": "c_uint32"},
        "debuginsn": {"type": "c_uint32"},
        # "execdata": {"type": "c_uint32"},
        "gclist": {"type": "c_uint32"},
        "sizecode": {"type": "c_int32"},
        "sizep": {"type": "c_int32"},
        "sizelocvars": {"type": "c_int32"},
        "sizeupvalues": {"type": "c_int32"},
        "sizek": {"type": "c_int32"},
        "sizelineinfo": {"type": "c_int32"},
        "linegaplog2": {"type": "c_int32"},
        "linedefined": {"type": "c_int32"},
        "bytecodeid": {"type": "c_int32"},

        "nups": {"type": "c_uint8"},
        "numparams": {"type": "c_uint8"},
        "is_vararg": {"type": "c_uint8"},
        "maxstacksize": {"type": "c_uint8"},
    }
    _field_fixups_ = {
        "k": "TValue*",
        "code": "Instruction*",
        "p": "Proto**",
        "lineinfo": "c_uint8*",
        "abslineinfo": "c_uint32*",
        "locvars": "LocVar*",
        "upvalues": "TString**",
        "source": "TString*",
        "debugname": "TString*",
        "debuginsn": "c_uint8*",
        # "execdata": "c_void*",
        "gclist": "GCObject*",
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()

    def get_next_gco(self):
        return self.addr + self.get_total_size()

class LuauRW_ProtoECB(LuauRW_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TPROTO
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},

        "k": {"type": "c_uint32"},
        "code": {"type": "c_uint32"},
        "p": {"type": "c_uint32"},
        "lineinfo": {"type": "c_uint32"},
        "abslineinfo": {"type": "c_uint32"},
        "locvars": {"type": "c_uint32"},
        "upvalues": {"type": "c_uint32"},
        "source": {"type": "c_uint32"},
        "debugname": {"type": "c_uint32"},
        "debuginsn": {"type": "c_uint32"},
        "execdata": {"type": "c_uint32"},
        "gclist": {"type": "c_uint32"},
        "sizecode": {"type": "c_int32"},
        "sizep": {"type": "c_int32"},
        "sizelocvars": {"type": "c_int32"},
        "sizeupvalues": {"type": "c_int32"},
        "sizek": {"type": "c_int32"},
        "sizelineinfo": {"type": "c_int32"},
        "linegaplog2": {"type": "c_int32"},
        "linedefined": {"type": "c_int32"},
        "bytecodeid": {"type": "c_int32"},

        "nups": {"type": "c_uint8"},
        "numparams": {"type": "c_uint8"},
        "is_vararg": {"type": "c_uint8"},
        "maxstacksize": {"type": "c_uint8"},
    }
    _field_fixups_ = {
        "k": "TValue*",
        "code": "Instruction*",
        "p": "Proto**",
        "lineinfo": "c_uint8*",
        "abslineinfo": "c_uint32*",
        "locvars": "LocVar*",
        "upvalues": "TString**",
        "source": "TString*",
        "debugname": "TString*",
        "debuginsn": "c_uint8*",
        "execdata": "c_void*",
        "gclist": "GCObject*",
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_ClosureContinuation(LuauRW_BaseStruct):
    __field_def__ = {
        "f": {"type": "c_uint32"},
        "cont": {"type": "c_uint32"},
        "debugname": {"type": "c_uint32"},
        "upvals": {"type": "LuauRW_UpVal"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "f": "lua_CFunction",
        "cont": "lua_Continuation",
        "debugname": "c_uint8*",
    }


class LuauRW_ClosureProto(LuauRW_BaseStruct):
    __field_def__ = {
        "p": {"type": "c_uint32"},
        "uprefs": {"type": "LuauRW_UpVal"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "p": "Proto*",
    }


class LuauRW_ClosureUnion(LuauRW_BaseStruct):
    __field_def__ = {
        "c": {"type": "LuauRW_ClosureContinuation"},
        "uprefs": {"type": "LuauRW_ClosureProto"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_Closure(LuauRW_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TCLOSURE
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},

        "isC": {"type": "c_uint8"},
        "nupvalues": {"type": "c_uint8"},
        "stacksize": {"type": "c_uint8"},
        "preload": {"type": "c_uint8"},

        "gclist": {"type": "c_uint32"},
        "env": {"type": "c_uint32"},
        "__anonymous__": {"type": "LuauRW_ClosureUnion"}
    }
    _field_fixups_ = {
        "gclist": "GCObject*",
        "env": "Table*",

        "k": "TValue*",
        "code": "Instruction*",
        "p": "Proto**",
        "lineinfo": "c_uint8*",
        "abslineinfo": "c_uint32*",
        "locvars": "LocVar*",
        "upvalues": "TString**",
        "source": "TString*",
        "debugname": "TString*",
        "debuginsn": "c_uint8*",
        "execdata": "c_void*",

    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()

    def get_next_gco(self):
        return self.addr + self.get_total_size()
class LuauRW_TKey(LuauRW_BaseStruct):
    __field_def__ = {
        "value": {"type": "LuauRW_Value"},
        "extra": {"type": "c_uint32"},
        "tt": {"type": "c_uint32", "bits": 4},
        "next": {"type": "c_uint32", "bits": 28},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_LuaNode(LuauRW_BaseStruct):
    __field_def__ = {
        "val": {"type": "LuauRW_TValue"},
        "key": {"type": "LuauRW_TKey"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_CallInfo(LuauRW_BaseStruct):
    __field_def__ = {
        "base": {"type": "c_uint32"},
        "func": {"type": "c_uint32"},
        "top": {"type": "c_uint32"},

        "savedpc": {"type": "c_uint32"},
        "nresults": {"type": "c_uint32"},
        "flags": {"type": "c_uint32"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "base": "TValue*",
        "func": "TValue*",
        "top": "TValue*",

        "savedpc": "Instruction*",
    }


class LuauRW_GCStats(LuauRW_BaseStruct):
    __field_def__ = {
        "triggerterms": {"type": "c_uint32*32"},
        "triggertermpos": {"type": "c_uint32"},
        "triggerintegral": {"type": "c_int32"},

        "atomicstarttotalsizebytes": {"type": "c_uint32"},
        "endtotalsizebytes": {"type": "c_uint32"},
        "heapgoalsizebytes": {"type": "c_uint32"},

        "starttimestamp": {"type": "c_double"},
        "atomicstarttimestamp": {"type": "c_double"},
        "endtimestamp": {"type": "c_double"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_lua_ExecutionCallbacks(LuauRW_BaseStruct):
    __field_def__ = {
        "context": {"type": "c_uint32"},
        "close": {"type": "c_uint32"},
        "destroy": {"type": "c_uint32"},
        "enter": {"type": "c_uint32"},
        "setbreakpoint": {"type": "c_uint32"},

    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "context": "c_void_p",
        "close": "void (*close)(lua_State* L)",
        "destroy": "void (*destroy)(lua_State* L, Proto* proto)",
        "enter": "int (*enter)(lua_State* L, Proto* proto);",
        "setbreakpoint": "void (*setbreakpoint)(lua_State* L, Proto* proto, int line)",
    }


class LuauRW_lua_Callbacks(LuauRW_BaseStruct):
    __field_def__ = {
        "userdata": {"type": "c_uint32"},
        "interrupt": {"type": "c_uint32"},
        "panic": {"type": "c_uint32"},
        "userthread": {"type": "c_uint32"},
        "useratom": {"type": "c_uint32"},

        "debugbreak": {"type": "c_uint32"},
        "debugstep": {"type": "c_uint32"},
        "debuginterrupt": {"type": "c_uint32"},
        "debugprotectederror": {"type": "c_uint32"},

    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "userdata": "c_void_p",
        "interrupt": "void (*interrupt)(lua_State* L, int gc)",
        "panic": "void (*panic)(lua_State* L, int errcode)",

        "userthread": "void (*userthread)(lua_State* LP, lua_State* L)",
        "useratom": "int16_t (*useratom)(const char* s, size_t l)",
        "debugbreak": "void (*debugbreak)(lua_State* L, lua_Debug* ar)",
        "debugstep": "void (*debugstep)(lua_State* L, lua_Debug* ar)",
        "debuginterrupt": "void (*debuginterrupt)(lua_State* L, lua_Debug* ar)",
        "debugprotectederror": "void (*debugprotectederror)(lua_State* L)",

    }


class LuauRW_stringtable(LuauRW_BaseStruct):
    __field_def__ = {
        "hash": {"type": "c_uint32"},
        "nuse": {"type": "c_uint32"},
        "size": {"type": "c_int32"},
        "enter": {"type": "c_uint32"},

    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "hash": "TString**",
    }


class LuauRW_lua_State(LuauRW_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TTHREAD
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},

        "status": {"type": "c_uint8"},
        "activememcat": {"type": "c_uint8"},
        "isactive": {"type": "c_uint8"},
        "singlestep": {"type": "c_uint8"},

        "top": {"type": "c_uint32"},
        "base": {"type": "c_uint32"},
        "global": {"type": "c_uint32"},
        "ci": {"type": "c_uint32"},
        "stack_last": {"type": "c_uint32"},
        "stack": {"type": "c_uint32"},

        "end_ci": {"type": "c_uint32"},
        "base_ci": {"type": "c_uint32"},

        "stacksize": {"type": "c_int32"},
        "size_ci": {"type": "c_int32"},

        "nCcalls": {"type": "c_uint16"},
        "baseCcalls": {"type": "c_uint16"},

        "cachedslot": {"type": "c_int32"},

        "gt": {"type": "c_uint32"},
        "openupval": {"type": "c_uint32"},
        "gclist": {"type": "c_uint32"},

        "namecall": {"type": "c_uint32"},

        "userdata": {"type": "c_uint32"},

    }
    _field_fixups_ = {

        "base": "TValue*",
        "top": "TValue*",

        "global": "global_State*",
        "ci": "CallInfo*",
        "stack_last": "TValue*",
        "stack": "TValue*",

        "end_ci": "CallInfo*",
        "base_ci": "CallInfo*",

        "gt": "Table*",
        "openupval": "UpVal*",
        "gclist": "GCObject*",

        "namecall": "TString*",

        "userdata": "c_void_p",
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()
    def get_next_gco(self):
        return self.addr + self.get_total_size()
class LuauRW_global_State(LuauRW_BaseStruct):
    __field_def__ = {
        "strt": {"type": "LuauRW_stringtable"},

        "frealloc": {"type": "c_uint32"},
        "ud": {"type": "c_uint32"},

        "currentwhite": {"type": "c_uint8"},
        "gcstate": {"type": "c_uint8"},

        "gray": {"type": "c_uint32"},
        "grayagain": {"type": "c_uint32"},
        "weak": {"type": "c_uint32"},

        "GCthreshold": {"type": "c_uint32"},
        "totalbytes": {"type": "c_uint32"},

        "gcgoal": {"type": "c_int32"},
        "gcstepmul": {"type": "c_int32"},
        "gcstepsize": {"type": "c_int32"},

        "freepages": {"type": "c_uint32*LUA_SIZECLASSES"},
        "freecopages": {"type": "c_uint32*LUA_SIZECLASSES"},
        "allgcopages": {"type": "c_uint32"},
        "sweepgcopages": {"type": "c_uint32"},

        "memcatbytes": {"type": "c_uint32*LUA_MEMORY_CATEGORIES"},

        "mainthread": {"type": "c_uint32"},

        "uvhead": {"type": "LuauRW_UpVal"},

        "mt": {"type": "c_uint32 * LUA_T_COUNT"},
        "ttname": {"type": "c_uint32 * LUA_T_COUNT"},
        "tmname": {"type": "c_uint32 * TMS_CNT"},
        "pseudotemp": {"type": "LuauRW_TValue"},
        "registry": {"type": "c_int32"},
        "errorjmp": {"type": "c_uint32"},
        "rngstate": {"type": "c_uint64"},
        "ptrenckey": {"type": "c_uint64*4"},
        "udatagc": {"type": "c_uint32"},
        "cb": {"type": "LuauRW_lua_Callbacks"},
        "ecb": {"type": "LuauRW_lua_ExecutionCallbacks"},
        "gcstats": {"type": "LuauRW_GCStats"},
    }
    _field_fixups_ = {

        "freealloc": "void* (*lua_Alloc)(void* ud, void* ptr, size_t osize, size_t nsize)",
        "ud": "void* (*lua_Alloc)(void* ud, void* ptr, size_t osize, size_t nsize)*",

        "gray": "GCObject*",
        "grayagain": "GCObject*",
        "weak": "GCObject*",

        "freepages": "lua_Page* [LUA_SIZECLASSES]",
        "freecopages": "lua_Page* [LUA_SIZECLASSES]",
        "allgcopages": "lua_Page*",
        "sweepgcopages": "lua_Page*",

        "memcatbytes": "c_uint32 [LUA_MEMORY_CATEGORIES]",

        "mainthread": "lua_State*",
        "mt": "Table* [LUA_T_COUNT]",
        "ttname": "TString* [LUA_T_COUNT]",
        "tmname": "TString* [LUA_T_COUNT]",
        "udatagc": "void (*udatagc[LUA_UTAG_LIMIT])(lua_State*, void*)",

    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_GCObjectUnion(LuauRW_BaseUnion):
    _gco_ = True
    _has_sanity_check_ = True
    __field_def__ = {
        "gch": {"type": "LuauRW_GCHeader"},
        "ts": {"type": "LuauRW_TString"},
        "u": {"type": "LuauRW_Udata"},
        "cl": {"type": "LuauRW_Closure"},
        "h": {"type": "LuauRW_Table"},
        "p": {"type": "LuauRW_Proto"},
        "uv": {"type": "LuauRW_UpVal"},
        "th": {"type": "LuauRW_lua_State"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        for x in self._fields_:
            name, fld = x[:2]
            obj = getattr(self, name)
            if obj.is_valid_gc_header():
                return True
        return False



class LuauRW_lua_Page(LuauRW_BaseStruct):
    __field_def__ = {
        "prev": {"type": "c_uint32"},
        "next": {"type": "c_uint32"},

        "gcolistprev": {"type": "c_uint32"},
        "gcolistnext": {"type": "c_uint32"},

        "pageSize": {"type": "c_int32"},
        "blockSize": {"type": "c_int32"},

        "freeList": {"type": "c_uint32"},
        "freeNext": {"type": "c_int32"},
        "busyBlocks": {"type": "c_int32"},

        "data": {"type": "LuauRW_ForceAlignment"},

    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {

        "prev": "lua_Page*",
        "next": "lua_Page*",

        "gcolistprev": "lua_Page*",
        "gcolistnext": "lua_Page*",

        "global": "global_State*",
        "ci": "CallInfo*",
        "stack_last": "TValue*",
        "stack": "TValue*",

        "end_ci": "CallInfo*",
        "base_ci": "CallInfo*",

        "gt": "Table*",
        "openupval": "UpVal*",
        "gclist": "GCObject*",

        "namecall": "TString*",

        "userdata": "c_void_p",
    }


class LuauRW_LG(LuauRW_BaseStruct):
    __field_def__ = {
        "l": {"type": "LuauRW_lua_State"},
        "g": {"type": "LuauRW_global_State"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)


class LuauRW_CodeAllocator(LuauRW_BaseStruct):
    __field_def__ = {
        "context": {"type": "c_uint32"},
        "createBlockUnwindInfo": {"type": "c_uint32"},
        "destroyBlockUnwindInfo": {"type": "c_uint32"},
        "kMaxReservedDataSize": {"type": "c_uint32"},
        "blockPos": {"type": "c_uint32"},
        "blockEnd": {"type": "c_uint32"},
        "blocks": {"type": "c_uint32"},
        "maxTotalSize": {"type": "c_uint32"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        # TODO Fill this in
    }


class LuauRW_NativeFallBack(LuauRW_BaseStruct):
    __field_def__ = {
        "fallback": {"type": "c_uint32"},
        "flags": {"type": "c_uint8"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        # "fallback": "const Instruction*(lua_State* L, const Instruction* pc, StkId base, TValue* k)",
    }


class LuauRW_NativeProto(LuauRW_BaseStruct):
    __field_def__ = {
        "entryTarget": {"type": "c_uint32"},
        "instTargets": {"type": "c_uint32"},

        "proto": {"type": "c_uint32"},
        "location": {"type": "c_uint32"},

    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        # "entryTarget": "uint32_t*",
        # "instTargets": "uint32_t**",
        "proto": "LuauRW_Proto*",
    }


class LuauRW_NativeContext(LuauRW_BaseStruct):
    __field_def__ = {
        "gateEntry": {"type": "c_uint32"},
        "gateExit": {"type": "c_uint32"},

        "fallback": {"type": "LuauRW_NativeFallBack*LOP__COUNT"},
        "luauF_table": {"type": "c_uint32*256"},

        "luaV_lessthan": {'type': 'c_uint32'},
        "luaV_lessequal": {'type': 'c_uint32'},
        "luaV_equalval": {'type': 'c_uint32'},
        "luaV_doarith": {'type': 'c_uint32'},
        "luaV_dolen": {'type': 'c_uint32'},
        "luaV_prepareFORN": {'type': 'c_uint32'},
        "luaV_gettable": {'type': 'c_uint32'},
        "luaV_settable": {'type': 'c_uint32'},
        "luaV_getimport": {'type': 'c_uint32'},
        "luaV_concat": {'type': 'c_uint32'},
        "luaH_getn": {'type': 'c_uint32'},
        "luaH_new": {'type': 'c_uint32'},
        "luaH_clone": {'type': 'c_uint32'},
        "luaH_resizearray": {'type': 'c_uint32'},
        "luaC_barriertable": {'type': 'c_uint32'},
        "luaC_barrierf": {'type': 'c_uint32'},
        "luaC_barrierback": {'type': 'c_uint32'},
        "luaC_step": {'type': 'c_uint32'},
        "luaF_close": {'type': 'c_uint32'},
        "TValue": {'type': 'c_uint32'},
        "libm_exp": {'type': 'c_uint32'},
        "libm_pow": {'type': 'c_uint32'},
        "libm_fmod": {'type': 'c_uint32'},
        "libm_asin": {'type': 'c_uint32'},
        "libm_sin": {'type': 'c_uint32'},
        "libm_sinh": {'type': 'c_uint32'},
        "libm_acos": {'type': 'c_uint32'},
        "libm_cos": {'type': 'c_uint32'},
        "libm_cosh": {'type': 'c_uint32'},
        "libm_atan": {'type': 'c_uint32'},
        "libm_atan2": {'type': 'c_uint32'},
        "libm_tan": {'type': 'c_uint32'},
        "libm_tanh": {'type': 'c_uint32'},
        "libm_log": {'type': 'c_uint32'},
        "libm_log2": {'type': 'c_uint32'},
        "libm_log10": {'type': 'c_uint32'},
        "libm_ldexp": {'type': 'c_uint32'},
        "libm_round": {'type': 'c_uint32'},
        "libm_frexp": {'type': 'c_uint32'},
        "libm_modf": {'type': 'c_uint32'},
        "forgLoopNodeIter": {'type': 'c_uint32'},
        "forgLoopNonTableFallback": {'type': 'c_uint32'},
        "forgPrepXnextFallback": {'type': 'c_uint32'},
        "callProlog": {'type': 'c_uint32'},
        "callEpilogC": {'type': 'c_uint32'},

    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        # TODO Fill this in

        "luaV_lessthan": "int (*luaV_lessthan)(lua_State* L, const TValue* l, const TValue* r)",
        "luaV_lessequal": "int (*luaV_lessequal)(lua_State* L, const TValue* l, const TValue* r)",
        "luaV_equalval": "int (*luaV_equalval)(lua_State* L, const TValue* t1, const TValue* t2)",
        "luaV_doarith": "void (*luaV_doarith)(lua_State* L, StkId ra, const TValue* rb, const TValue* rc, TMS op)",
        "luaV_dolen": "void (*luaV_dolen)(lua_State* L, StkId ra, const TValue* rb)",
        "luaV_prepareFORN": "void (*luaV_prepareFORN)(lua_State* L, StkId plimit, StkId pstep, StkId pinit)",
        "luaV_gettable": "void (*luaV_gettable)(lua_State* L, const TValue* t, TValue* key, StkId val)",
        "luaV_settable": "void (*luaV_settable)(lua_State* L, const TValue* t, TValue* key, StkId val)",
        "luaV_getimport": "void (*luaV_getimport)(lua_State* L, Table* env, TValue* k, uint32_t id, bool propagatenil)",
        "luaV_concat": "void (*luaV_concat)(lua_State* L, int total, int last)",
        "luaH_getn": "int (*luaH_getn)(Table* t)",
        "luaH_new": "Table* (*luaH_new)(lua_State* L, int narray, int lnhash)",
        "luaH_clone": "Table* (*luaH_clone)(lua_State* L, Table* tt)",
        "luaH_resizearray": "void (*luaH_resizearray)(lua_State* L, Table* t, int nasize)",
        "luaC_barriertable": "void (*luaC_barriertable)(lua_State* L, Table* t, GCObject* v)",
        "luaC_barrierf": "void (*luaC_barrierf)(lua_State* L, GCObject* o, GCObject* v)",
        "luaC_barrierback": "void (*luaC_barrierback)(lua_State* L, GCObject* o, GCObject** gclist)",
        "luaC_step": "size_t (*luaC_step)(lua_State* L, bool assist)",
        "luaF_close": "void (*luaF_close)(lua_State* L, StkId level)",
        "TValue": "const TValue* (*luaT_gettm)(Table* events, TMS event, TString* ename)",
        "libm_exp": "double (*libm_exp)(double)",
        "libm_pow": "double (*libm_pow)(double, double)",
        "libm_fmod": "double (*libm_fmod)(double, double)",
        "libm_asin": "double (*libm_asin)(double)",
        "libm_sin": "double (*libm_sin)(double)",
        "libm_sinh": "double (*libm_sinh)(double)",
        "libm_acos": "double (*libm_acos)(double)",
        "libm_cos": "double (*libm_cos)(double)",
        "libm_cosh": "double (*libm_cosh)(double)",
        "libm_atan": "double (*libm_atan)(double)",
        "libm_atan2": "double (*libm_atan2)(double, double)",
        "libm_tan": "double (*libm_tan)(double)",
        "libm_tanh": "double (*libm_tanh)(double)",
        "libm_log": "double (*libm_log)(double)",
        "libm_log2": "double (*libm_log2)(double)",
        "libm_log10": "double (*libm_log10)(double)",
        "libm_ldexp": "double (*libm_ldexp)(double, int)",
        "libm_round": "double (*libm_round)(double)",
        "libm_frexp": "double (*libm_frexp)(double, int*)",
        "libm_modf": "double (*libm_modf)(double, double*)",
        "forgLoopNodeIter": "bool (*forgLoopNodeIter)(lua_State* L, Table* h, int index, TValue* ra)",
        "forgLoopNonTableFallback": "bool (*forgLoopNonTableFallback)(lua_State* L, int insnA, int aux)",
        "forgPrepXnextFallback": "void (*forgPrepXnextFallback)(lua_State* L, TValue* ra, int pc)",
        "callProlog": "Closure* (*callProlog)(lua_State* L, TValue* ra, StkId argtop, int nresults)",
        "callEpilogC": "void (*callEpilogC)(lua_State* L, int nresults, int n)",
    }


class LuauRW_NativeState(LuauRW_BaseStruct):
    __field_def__ = {
        "codeAllocator": {"type": "LuauRW_CodeAllocator"},
        "unwindBuilder": {"type": "c_uint32"},
        "gateData": {"type": "c_uint32"},
        "gateDataSize": {"type": "c_uint32"},
        "context": {"type": "LuauRW_NativeContext"},

    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "unwindBuilder": "std::unique_ptr<UnwindBuilder>",
        "gateData": "uint8_t*",
    }


class LuauRW_ConstantValue(LuauRW_BaseUnion):
    __field_def__ = {
        "valueBoolean": {"type": "c_uint32"},
        "valueNumber": {"type": "c_double"},
        "valueString": {"type": "c_uint32"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _type_enums_ = [i for i in COMPILER_TYPES_MAPPING.values() if isinstance(i, int)]
    _type_string_enums_ = [COMPILER_TYPES_MAPPING[i] for i in COMPILER_TYPES_MAPPING.values() if isinstance(i, int)]


class LuauRW_Constant(LuauRW_BaseStruct):
    __field_def__ = {
        "type": {"type": "c_uint32"},
        "stringLength": {"type": "c_uint32"},
        "__anonymous__": {"type": "LuauRW_ConstantValue"},
    }
    _fields_ = LuauRW_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRW_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {}
    _type_enums_ = [i for i in COMPILER_TYPES_MAPPING.values() if isinstance(i, int)]
    _type_string_enums_ = [COMPILER_TYPES_MAPPING[i] for i in COMPILER_TYPES_MAPPING.values() if isinstance(i, int)]

    def __init__(self, **kargs):
        super(LuauRW_Constant, self).__init__(**kargs)
        self.gch = LuauRW_GCHeader(**kargs)
        sz = sizeof(self)
        str_len = self.end - (self.addr + sz) + self.word_sz
        buf = kargs.get('buf', None)
        setattr(self, 'data', None)
        if buf and len(buf) > sz:
            value = "".join([chr(x) for x in buf[sz:sz + str_len]])
            setattr(self, 'data', value)
            setattr(self, '__value', value)
            setattr(self, '__value_offset', sz)

    def is_type(self, type_string):
        return self.type == COMPILER_TYPES_MAPPING[type_string]

    def is_string(self):
        return self.is_type('string')

    def is_number(self):
        return self.is_type('number')

    def is_boolean(self):
        return self.is_type('boolean')

    def is_nil(self):
        return self.is_type('nil')

    def get_value_offset(self):
        return getattr(self, '__value_offset', None)

    @classmethod
    def deserialize(cls, addr, nbytes, analysis=None, word_sz=4):
        f = cls(addr=addr, analysis=analysis, buf=nbytes, word_sz=word_sz)
        return f

    def get_dump(self, addr=None, offset=0, word_sz=None):
        r, flat = super(LuauRW_Constant, self).get_dump( word_sz=None)
        vo = self.get_value_offset()
        addr = getattr(self, 'addr') if hasattr(self, 'addr') else 0
        addr = addr + vo if vo is not None else addr
        if vo is not None:
            x = {"name": "data", "value": self.get_value()[:80], "addr": addr, 'type': 'char[]', 'offset': vo,
                 "fmt": "{}", "is_array": False}
            r[x['addr']] = x
            flat.append(x)
        else:
            x = {"name": "data", "value": None, "addr": addr, 'type': None, 'offset': vo,
                 "fmt": "{}", "is_array": False}
        return r, flat


FIXUP_TYPE_MAPPING = {
    "TString": LuauRW_TString,
    "GCObject": LuauRW_GCObjectUnion,
    "global_State": LuauRW_global_State,
    "lua_State": LuauRW_lua_State,
    "TValue": LuauRW_TValue,
    "Value": LuauRW_Value,
    "UpVal": LuauRW_UpVal,
    "CallInfo": LuauRW_CallInfo,
    "Instruction": ctypes.c_uint32,
    "lua_Page": LuauRW_lua_Page,
    "LuaNode": LuauRW_LuaNode,
}

VALID_OBJ_CLS_MAPPING = {
    TSTRING: LuauRW_TString,
    TTABLE: LuauRW_Table,
    TCLOSURE: LuauRW_Closure,
    TUSERDATA: LuauRW_Udata,
    TTHREAD: LuauRW_lua_State,
    TPROTO: LuauRW_Proto,
    TUPVAL: LuauRW_UpVal,
}


GCO_TT_MAPPING = {
    TSTRING: LuauRW_TString,
    TUPVAL: LuauRW_UpVal,
    TTHREAD: LuauRW_lua_State,
    TCLOSURE: LuauRW_Closure,
    TTABLE: LuauRW_Table,
    TPROTO: LuauRW_ProtoECB,
    TUSERDATA: LuauRW_Udata
}

GCO_NAME_MAPPING = {
    TSTRING: LuauRW_TString,
    TUPVAL: LuauRW_UpVal,
    TTHREAD: LuauRW_lua_State,
    TCLOSURE: LuauRW_Closure,
    TTABLE: LuauRW_Table,
    TPROTO: LuauRW_ProtoECB,
    TUSERDATA: LuauRW_Udata,
}