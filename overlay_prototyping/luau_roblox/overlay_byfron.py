import ctypes
import struct
from ctypes import *

from overlay_prototyping.luau_roblox.consts import *

from overlay_prototyping.transmute.base_le_structs import Transmute_BaseLES
from overlay_prototyping.transmute.base_le_union import Transmute_BaseLEU



class LuauRWB_GCHeader(Transmute_BaseLES):
    _gco_ = True
    _has_sanity_check_ = True
    __field_def__ = {
        "gch_field_0": {"type": "c_uint8"},
        "gch_field_1": {"type": "c_uint8"},
        "gch_field_2": {"type": "c_uint8"},
        "gch_field_3": {"type": "c_uint8"},
    }
    _fields_ = Transmute_BaseLES.create_fields(__field_def__)
    _fields_dict_ = Transmute_BaseLES.create_fields_dict(__field_def__)
    _fields_alias_ = {}
    # {
    #     "gch_marked": "gch_field_1",
    #     "gch_tt": "gch_field_0",
    #     "gch_memcat": "gch_field_2",
    #     "gch_padding": "gch_field_3"
    # }

    @classmethod
    def update_alias_by_ordered_list(cls, alias_fields=None, ordered_fields=None):
        af = alias_fields if alias_fields else GCH_FIELD_DEFAULT_ORDER
        of = ordered_fields if ordered_fields else GCH_ORDERED_FIELDS
        return super(LuauRWB_GCHeader, cls).update_alias_by_ordered_list(af, of)

    @property
    def tt(self):
        return self.unalias_field('gch_tt')

    @property
    def marked(self):
        return self.unalias_field('gch_marked')

    @property
    def memcat(self):
        return self.unalias_field('gch_memcat')

    @property
    def gch_padding(self):
        return self.unalias_field('gch_padding')

    def __init__(self, **kargs):
        super(LuauRWB_GCHeader, self).__init__(**kargs)

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

class LuauRWB_BaseStruct(Transmute_BaseLES):
    _OVERLAY_TYPE_ = 'LuauRW'
    _fields_ = []
    _fields_dict_ = {}
    _is_union_ = False
    _field_fixups_ = {}
    _gco_ = False
    _tt_ = None
    _init_required_ = True
    _gc_header_cls_ = LuauRWB_GCHeader
    _fields_alias_ = {}
    # {
    #     "gch_marked": "gch_field_1",
    #     "gch_tt": "gch_field_0",
    #     "gch_memcat": "gch_field_2",
    #     "gch_padding": "gch_field_3"
    # }

    @classmethod
    def update_alias_by_ordered_list(cls, alias_fields=None, ordered_fields=None):
        af = alias_fields if alias_fields else GCH_FIELD_DEFAULT_ORDER
        of = ordered_fields if ordered_fields else GCH_ORDERED_FIELDS
        return super(LuauRWB_BaseStruct, cls).update_alias_by_ordered_list(af, of)

    @property
    def tt(self):
        return self.unalias_field('gch_tt')

    @property
    def marked(self):
        return self.unalias_field('gch_marked')

    @property
    def memcat(self):
        return self.unalias_field('gch_memcat')

    @property
    def gch_padding(self):
        return self.unalias_field('gch_padding')

    @classmethod
    def create_fields(cls, json_fields):
        return [(k, eval(v['type']), v['bits']) if 'bits' in v else (k, eval(v['type'])) for k, v in
                json_fields.items()]

    @classmethod
    def create_fields_dict(cls, json_fields):
        return dict((k, eval(v['type'])) if 'bits' in v else (k, eval(v['type'])) for k, v in
                    json_fields.items())
    def __init__(self, **kargs):
        super(LuauRWB_BaseStruct, self).__init__(**kargs)
        # buf = kargs.get('buf', None)
        # if isinstance(buf, bytes):
        #     fit = min(len(buf), sizeof(self))
        #     memmove(addressof(self), buf, fit)
        # self.initialize_with_kargs(**kargs)

    @property
    def expected_tt(self):
        return getattr(self, '_tt_', None)

    def get_gch(self):
        fld = None
        if not self._gco_ or self._gc_header_cls_ is None:
            return None
        if hasattr(self, '_cached_gch'):
            return getattr(self, '_cached_gch')
        elif hasattr(self, 'tt') and hasattr(self, 'marked') and hasattr(self, 'gch_padding'):
            fld = self
        elif self.__class__.__name__.find('LuauRWB_GCHeader') > -1:
            fld = self
        else:
            for x in self._fields_:
                name, fld = x[:2]
                if fld.__name__.find('LuauRWB_GCHeader') > -1:
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


class LuauRWB_BaseUnion(Transmute_BaseLEU):
    _OVERLAY_TYPE_ = 'LuauRW'
    _fields_ = []
    _fields_dict_ = {}
    _is_union_ = True
    _field_fixups_ = {}
    _gco_ = False
    _tt_ = None
    _init_required_ = True
    _gc_header_cls_ = LuauRWB_GCHeader

    def __init__(self, **kargs):
        super(LuauRWB_BaseUnion, self).__init__(**kargs)
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
        elif self.__class__.__name__.find('LuauRWB_GCHeader') > -1:
            fld = self
        else:
            for x in self._fields_:
                name, fld_type = x[:2]
                if fld_type.__name__.find('LuauRWB_GCHeader') > -1:
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


class LuauRWB_Value(LuauRWB_BaseUnion):
    _OVERLAY_TYPE_ = 'LuauRW'
    __field_def__ = {
        "gc": {"type": "c_uint64"},
        "p": {"type": "c_uint64"},
        "n": {"type": "c_double"},
        "b": {"type": "c_int32"},
        "v": {"type": "c_float"},
    }
    _field_fixups_ = {"gc": "GCObject*", "p": "void*"}
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)

class LuauRWB_TValue(LuauRWB_BaseStruct):
    _OVERLAY_TYPE_ = 'LuauRW'
    __field_def__ = {
        "value": {"type": "LuauRWB_Value"},
        "extra": {"type": "c_uint32*1"},
        "tvalue_tt": {"type": "c_uint32"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _fields_alias_ = {
        "tvalue_tt": "tvalue_tt"
    }

    @property
    def tt(self):
        return self.unalias_field("tvalue_tt")

class LuauRWB_TString(LuauRWB_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TSTRING
    __field_def__ = {
        "gch_field_0": {"type": "c_uint8"},
        "gch_field_1": {"type": "c_uint8"},
        "gch_field_2": {"type": "c_uint8"},
        "gch_field_3": {"type": "c_uint8"},
        "atom": {"type": "c_uint16"},
        "next": {"type": "c_uint64"},
        "hash": {"type": "c_uint32"},
        "end": {"type": "c_uint32"},
        # "data": {"type": "c_char"},
    }
    _field_fixups_ = {
        "metatable": "Table*",
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _calc_str_len_ = "basic"

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
        r, flat = super(LuauRWB_TString, self).get_dump( word_sz=None)

        addr = self.addr if self.addr is not None and self.addr > 0 else addr
        # addr = getattr(self, 'addr') if hasattr(self, 'addr') else 0
        vo = self.get_value_offset()
        addr = addr + vo if vo is not None else addr
        v = self.get_value()
        if v is not None:
            x = {"name": "data", "value":v[:80], "addr": addr, 'type': 'char[]', 'offset': vo,
                 "fmt": "{}", "is_array": False}
            r[x['addr']] = x
            x = x.copy()
            flat.append(x)
        else:
            x = {"name": "data", "value": None, "addr": addr, 'type': None, 'offset': vo,
                 "fmt": "{}", "is_array": False}
        return r, flat

    def sanity_check(self):
        return self.is_valid_gc_header()

    def do_fixups(self, **kargs):
        sz = sizeof(self)
        str_len = self.calc_str_len()
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

    def calc_str_len(self):
        if self._calc_str_len_ == 'basic':
            return self.end - (self.addr + ctypes.sizeof(self)) + self.word_sz
        if self._calc_str_len_ == 'add_end_addr_value':
            return self.end + self.addr_of('end') & 0xffffffff
        return self.end - (self.addr + ctypes.sizeof(self)) + self.word_sz

    @classmethod
    def set_calc_strlen(cls, approach='basic'):
        cls._calc_str_len_ = approach


class LuauRWB_ForceAlignment(LuauRWB_BaseUnion):
    _OVERLAY_TYPE_ = 'LuauRW'
    __field_def__ = {
        "data": {"type": "c_uint8*1"},
        "align1": {"type": "c_double"},
        # "align2": {"type": "c_void_p"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)


class LuauRWB_Udata(LuauRWB_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TUSERDATA
    __field_def__ = {
        "gch_field_0": {"type": "c_uint8"},
        "gch_field_1": {"type": "c_uint8"},
        "gch_field_2": {"type": "c_uint8"},
        "gch_field_3": {"type": "c_uint8"},
        "tag": {"type": "c_uint8"},
        "len": {"type": "c_int32"},
        "metatable": {"type": "c_uint64"},
        "data": {"type": "LuauRWB_ForceAlignment"},
    }
    _field_fixups_ = {
        "metatable": "Table*",
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()

    def get_next_gco(self):
        return self.addr + self.get_total_size()

class LuauRWB_Proto(LuauRWB_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TPROTO
    __field_def__ = {
        "gch_field_0": {"type": "c_uint8"},
        "gch_field_1": {"type": "c_uint8"},
        "gch_field_2": {"type": "c_uint8"},
        "gch_field_3": {"type": "c_uint8"},

        "k": {"type": "c_uint64"},
        "code": {"type": "c_uint64"},
        "p": {"type": "c_uint64"},
        "lineinfo": {"type": "c_uint64"},
        "abslineinfo": {"type": "c_uint64"},
        "locvars": {"type": "c_uint64"},
        "upvalues": {"type": "c_uint64"},
        "source": {"type": "c_uint64"},
        "debugname": {"type": "c_uint64"},
        "debuginsn": {"type": "c_uint64"},
        # "execdata": {"type": "c_uint64"},
        "gclist": {"type": "c_uint64"},
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
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()

    def get_next_gco(self):
        return self.addr + self.get_total_size()

class LuauRWB_ProtoECB(LuauRWB_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TPROTO
    __field_def__ = {
        "gch_field_0": {"type": "c_uint8"},
        "gch_field_1": {"type": "c_uint8"},
        "gch_field_2": {"type": "c_uint8"},
        "gch_field_3": {"type": "c_uint8"},

        "k": {"type": "c_uint64"},
        "code": {"type": "c_uint64"},
        "p": {"type": "c_uint64"},
        "lineinfo": {"type": "c_uint64"},
        "abslineinfo": {"type": "c_uint64"},
        "locvars": {"type": "c_uint64"},
        "upvalues": {"type": "c_uint64"},
        "source": {"type": "c_uint64"},
        "debugname": {"type": "c_uint64"},
        "debuginsn": {"type": "c_uint64"},
        "execdata": {"type": "c_uint64"},
        "gclist": {"type": "c_uint64"},
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
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)




class LuauRWB_TableArrayBoundary(LuauRWB_BaseUnion):
    __field_def__ = {
        "lastfree": {"type": "c_uint32"},
        "aboundary": {"type": "c_uint32"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)


class LuauRWB_Table(LuauRWB_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TTABLE
    __field_def__ = {
        "gch_field_0": {"type": "c_uint8"},
        "gch_field_1": {"type": "c_uint8"},
        "gch_field_2": {"type": "c_uint8"},
        "gch_field_3": {"type": "c_uint8"},

        "tmcache": {"type": "c_uint8"},
        "readonly": {"type": "c_uint8"},
        "safeenv": {"type": "c_uint8"},
        "lsizenode": {"type": "c_uint8"},
        "nodemask8": {"type": "c_uint8"},
        "sizearray": {"type": "c_uint32"},
        # "lastfree_aboundary": {"type": "c_uint32"},
        #  Original
        # "__anonymous__": {"type": "LuauRWB_BaseUnionArrayBoundary"},
        # "metatable": {"type": "c_uint32"},  # Table*
        #  Swapped after some analysis
        "__anonymous__": {"type": "LuauRWB_TableArrayBoundary"},
        "metatable": {"type": "c_uint64"},  # Table*
        "array": {"type": "c_uint64"},
        "node": {"type": "c_uint64"},
        "gclist": {"type": "c_uint64"},
    }
    _field_fixups_ = {
        "metatable": "Table*",
        "array": "TValue*",
        "node": "LuaNode*",
        "gclist": "GCObject*"
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()

    def get_next_gco(self):
        return self.addr + self.get_total_size()-self.word_sz

    def get_tvalue_address(self, index):
        return self.addr + self.get_offset('array') + index * ctypes.sizeof(LuauRWB_TValue)

class LuauRWB_LocVar(LuauRWB_BaseStruct):
    __field_def__ = {
        "varname": {"type": "c_uint64"},  # TString*
        "startpc": {"type": "c_uint8"},
        "endpc": {"type": "c_uint8"},
        "reg": {"type": "c_uint8"},
    }
    _field_fixups_ = {"varname": "TString*"}
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)



class LuauRWB_UpValOpenUnion(LuauRWB_BaseUnion):
    __field_def__ = {
        "prev": {"type": "c_uint64"},
        "next": {"type": "c_uint64"},
        "thread": {"type": "c_uint64"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "prev": "UpVal*",
        "next": "UpVal*",
        "thread": "UpVal*",
    }


class LuauRWB_UpValUnion(LuauRWB_BaseUnion):
    __field_def__ = {
        "value": {"type": "LuauRWB_TValue"},
        "open": {"type": "LuauRWB_UpValOpenUnion"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)


class LuauRWB_UpVal(LuauRWB_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TUPVAL
    __field_def__ = {
        "gch_field_0": {"type": "c_uint8"},
        "gch_field_1": {"type": "c_uint8"},
        "gch_field_2": {"type": "c_uint8"},
        "gch_field_3": {"type": "c_uint8"},

        "markedopen": {"type": "c_int8"},
        "v": {"type": "c_uint64"},

        "u": {"type": "LuauRWB_UpValUnion"},
        # "metatable": {"type": "c_uint32"},
        # "data": {"type": "c_uint8*8"},
    }
    _field_fixups_ = {
        "v": "TValue*",
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()

    def get_next_gco(self):
        return self.addr + self.get_total_size()



class LuauRWB_ClosureContinuation(LuauRWB_BaseStruct):
    __field_def__ = {
        "f": {"type": "c_uint64"},
        "cont": {"type": "c_uint64"},
        "debugname": {"type": "c_uint64"},
        "upvals": {"type": "LuauRWB_UpVal"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "f": "lua_CFunction",
        "cont": "lua_Continuation",
        "debugname": "c_uint8*",
    }


class LuauRWB_ClosureProto(LuauRWB_BaseStruct):
    __field_def__ = {
        "p": {"type": "c_uint64"},
        "uprefs": {"type": "LuauRWB_UpVal"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "p": "Proto*",
    }


class LuauRWB_ClosureUnion(LuauRWB_BaseStruct):
    __field_def__ = {
        "c": {"type": "LuauRWB_ClosureContinuation"},
        "uprefs": {"type": "LuauRWB_ClosureProto"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)


class LuauRWB_Closure(LuauRWB_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TCLOSURE
    __field_def__ = {
        "gch_field_0": {"type": "c_uint8"},
        "gch_field_1": {"type": "c_uint8"},
        "gch_field_2": {"type": "c_uint8"},
        "gch_field_3": {"type": "c_uint8"},

        "isC": {"type": "c_uint8"},
        "nupvalues": {"type": "c_uint8"},
        "stacksize": {"type": "c_uint8"},
        "preload": {"type": "c_uint8"},

        "gclist": {"type": "c_uint64"},
        "env": {"type": "c_uint64"},
        "__anonymous__": {"type": "LuauRWB_ClosureUnion"}
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
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()

    def get_next_gco(self):
        return self.addr + self.get_total_size()
class LuauRWB_TKey(LuauRWB_BaseStruct):
    __field_def__ = {
        "value": {"type": "LuauRWB_Value"},
        "extra": {"type": "c_uint32"},
        "tkey_tt": {"type": "c_uint32", "bits": 4},
        "next": {"type": "c_uint32", "bits": 28},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _fields_alias_ = {
        "tkey_tt": "tkey_tt"
    }

    @property
    def tt(self):
        return self.unalias_field("tkey_tt")


class LuauRWB_LuaNode(LuauRWB_BaseStruct):
    __field_def__ = {
        "val": {"type": "LuauRWB_TValue"},
        "key": {"type": "LuauRWB_TKey"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)


class LuauRWB_CallInfo(LuauRWB_BaseStruct):
    __field_def__ = {
        "base": {"type": "c_uint64"},
        "func": {"type": "c_uint64"},
        "top": {"type": "c_uint64"},

        "savedpc": {"type": "c_uint64"},
        "nresults": {"type": "c_uint32"},
        "flags": {"type": "c_uint32"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "base": "TValue*",
        "func": "TValue*",
        "top": "TValue*",

        "savedpc": "Instruction*",
    }


class LuauRWB_GCStats(LuauRWB_BaseStruct):
    __field_def__ = {
        "triggerterms": {"type": "c_uint32*32"},
        "triggertermpos": {"type": "c_uint32"},
        "triggerintegral": {"type": "c_int32"},

        "atomicstarttotalsizebytes": {"type": "c_uint64"},
        "endtotalsizebytes": {"type": "c_uint64"},
        "heapgoalsizebytes": {"type": "c_uint64"},

        "starttimestamp": {"type": "c_double"},
        "atomicstarttimestamp": {"type": "c_double"},
        "endtimestamp": {"type": "c_double"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)


class LuauRWB_lua_ExecutionCallbacks(LuauRWB_BaseStruct):
    __field_def__ = {
        "context": {"type": "c_uint64"},
        "close": {"type": "c_uint64"},
        "destroy": {"type": "c_uint64"},
        "enter": {"type": "c_uint64"},
        "setbreakpoint": {"type": "c_uint64"},

    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "context": "c_void_p",
        "close": "void (*close)(lua_State* L)",
        "destroy": "void (*destroy)(lua_State* L, Proto* proto)",
        "enter": "int (*enter)(lua_State* L, Proto* proto);",
        "setbreakpoint": "void (*setbreakpoint)(lua_State* L, Proto* proto, int line)",
    }


class LuauRWB_lua_Callbacks(LuauRWB_BaseStruct):
    __field_def__ = {
        "userdata": {"type": "c_uint64"},
        "interrupt": {"type": "c_uint64"},
        "panic": {"type": "c_uint64"},
        "userthread": {"type": "c_uint64"},
        "useratom": {"type": "c_uint64"},

        "debugbreak": {"type": "c_uint64"},
        "debugstep": {"type": "c_uint64"},
        "debuginterrupt": {"type": "c_uint64"},
        "debugprotectederror": {"type": "c_uint64"},

    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
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


class LuauRWB_stringtable(LuauRWB_BaseStruct):
    __field_def__ = {
        "hash": {"type": "c_uint64"},
        "nuse": {"type": "c_uint32"},
        "size": {"type": "c_int32"},
        # "enter": {"type": "c_uint32"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "hash": "TString**",
    }


class LuauRWB_lua_State(LuauRWB_BaseStruct):
    _gco_ = True
    _has_sanity_check_ = True
    _tt_ = TTHREAD
    __field_def__ = {
        "gch_field_0": {"type": "c_uint8"},
        "gch_field_1": {"type": "c_uint8"},
        "gch_field_2": {"type": "c_uint8"},
        "gch_field_3": {"type": "c_uint8"},

        "status": {"type": "c_uint8"},
        "activememcat": {"type": "c_uint8"},
        "isactive": {"type": "c_uint8"},
        "singlestep": {"type": "c_uint8"},

        "top": {"type": "c_uint64"},
        "base": {"type": "c_uint64"},
        "global_State": {"type": "c_uint64"},
        "ci": {"type": "c_uint64"},
        "stack_last": {"type": "c_uint64"},
        "stack": {"type": "c_uint64"},

        "end_ci": {"type": "c_uint64"},
        "base_ci": {"type": "c_uint64"},

        "stacksize": {"type": "c_int32"},
        "size_ci": {"type": "c_int32"},

        "nCcalls": {"type": "c_uint16"},
        "baseCcalls": {"type": "c_uint16"},

        "cachedslot": {"type": "c_int32"},

        "gt": {"type": "c_uint64"},
        "openupval": {"type": "c_uint64"},
        "gclist": {"type": "c_uint64"},

        "namecall": {"type": "c_uint64"},

        "userdata": {"type": "c_uint64"},

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
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        return self.is_valid_gc_header()
    def get_next_gco(self):
        return self.addr + self.get_total_size()

class LuauRWB_lua_jmpbuf(LuauRWB_BaseStruct):
    __field_def__ = {
        "prev": {"type": "c_uint64"},
        "status": {"type": "c_uint32"},
        "buf": {"type": "c_uint64"},
    }

    _field_fixups_ = {
        "prev": "lua_jmpbuf*"
    }
class LuauRWB_global_State(LuauRWB_BaseStruct):
    __field_def__ = {
        "strt": {"type": "LuauRWB_stringtable"},

        "frealloc": {"type": "c_uint64"},
        "ud": {"type": "c_uint64"},

        "currentwhite": {"type": "c_uint8"},
        "gcstate": {"type": "c_uint8"},

        "gray": {"type": "c_uint64"},
        "grayagain": {"type": "c_uint64"},
        "weak": {"type": "c_uint64"},

        "GCthreshold": {"type": "c_uint64"},
        "totalbytes": {"type": "c_uint64"},

        "gcgoal": {"type": "c_int32"},
        "gcstepmul": {"type": "c_int32"},
        "gcstepsize": {"type": "c_int32"},

        "freepages": {"type": "c_uint64*LUA_SIZECLASSES"},
        "freecopages": {"type": "c_uint64*LUA_SIZECLASSES"},
        "allgcopages": {"type": "c_uint64"},
        "sweepgcopages": {"type": "c_uint64"},

        "memcatbytes": {"type": "c_uint32*LUA_MEMORY_CATEGORIES"},

        "mainthread": {"type": "c_uint64"},

        "uvhead": {"type": "LuauRWB_UpVal"},

        "mt": {"type": "c_uint64 * LUA_T_COUNT"},
        "ttname": {"type": "c_uint64 * LUA_T_COUNT"},
        "tmname": {"type": "c_uint64 * TMS_CNT"},
        "pseudotemp": {"type": "LuauRWB_TValue"},

        "registry": {"type": "TValue"},
        "registryfree": {"type": "c_int32"},

        "errorjmp": {"type": "c_uint64"},
        "rngstate": {"type": "c_uint64"},
        "ptrenckey": {"type": "c_uint64*4"},

        "cb": {"type": "LuauRWB_lua_Callbacks"},
        # TODO determine if this field is even valid in client
        "ecb": {"type": "LuauRWB_lua_ExecutionCallbacks"},
        "udatagc": {"type": "c_uint32"},
        "gcstats": {"type": "LuauRWB_GCStats"},
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
        "errorjmp":"lua_jmpbuf*",
        "udatagc": "void (*udatagc[LUA_UTAG_LIMIT])(lua_State*, void*)",

    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)


class LuauRWB_GCObjectUnion(LuauRWB_BaseUnion):
    _gco_ = True
    _has_sanity_check_ = True
    __field_def__ = {
        "gch": {"type": "LuauRWB_GCHeader"},
        "ts": {"type": "LuauRWB_TString"},
        "u": {"type": "LuauRWB_Udata"},
        "cl": {"type": "LuauRWB_Closure"},
        "h": {"type": "LuauRWB_Table"},
        "p": {"type": "LuauRWB_Proto"},
        "uv": {"type": "LuauRWB_UpVal"},
        "th": {"type": "LuauRWB_lua_State"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)

    def sanity_check(self):
        for x in self._fields_:
            name, fld = x[:2]
            obj = getattr(self, name)
            if obj.is_valid_gc_header():
                return True
        return False



class LuauRWB_lua_Page(LuauRWB_BaseStruct):
    __field_def__ = {
        "prev": {"type": "c_uint64"},
        "next": {"type": "c_uint64"},

        "gcolistprev": {"type": "c_uint64"},
        "gcolistnext": {"type": "c_uint64"},

        "pageSize": {"type": "c_int32"},
        "blockSize": {"type": "c_int32"},

        "freeList": {"type": "c_uint64"},
        "freeNext": {"type": "c_int32"},
        "busyBlocks": {"type": "c_int32"},

        "data": {"type": "LuauRWB_ForceAlignment"},

    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {

        "prev": "lua_Page*",
        "next": "lua_Page*",

        "gcolistprev": "lua_Page*",
        "gcolistnext": "lua_Page*",
        "gcolistnext": "void*",

    }


class LuauRWB_LG(LuauRWB_BaseStruct):
    __field_def__ = {
        "l": {"type": "LuauRWB_lua_State"},
        "g": {"type": "LuauRWB_global_State"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)


class LuauRWB_CodeAllocator(LuauRWB_BaseStruct):
    __field_def__ = {
        "context": {"type": "c_uint64"},
        "createBlockUnwindInfo": {"type": "c_uint64"},
        "destroyBlockUnwindInfo": {"type": "c_uint64"},
        "kMaxReservedDataSize": {"type": "c_uint64"},
        "blockPos": {"type": "c_uint64"},
        "blockEnd": {"type": "c_uint64"},
        "blocks": {"type": "c_uint64"},
        "unwindInfos": {"type": "c_uint64"},
        "blockSize": {"type": "c_uint64"},
        "maxTotalSize": {"type": "c_uint64"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "context":"void*",
        "createBlockUnwindInfo": "void* (*createBlockUnwindInfo)(void* context, uint8_t* block, size_t blockSize, size_t& startOffset)",
        "blocks": "std::vector<uint8_t*>",
        "unwindInfos": "std::vector<void*>",
    }


class LuauRWB_NativeFallBack(LuauRWB_BaseStruct):
    __field_def__ = {
        "fallback": {"type": "c_uint64"},
        "flags": {"type": "c_uint8"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        # "fallback": "const Instruction*(lua_State* L, const Instruction* pc, StkId base, TValue* k)",
    }


class LuauRWB_NativeProto(LuauRWB_BaseStruct):
    __field_def__ = {
        "instOffsets": {"type": "c_uint64"},
        "instBase": {"type": "c_uint64"},
        "entryTarget": {"type": "c_uint64"},
        "proto": {"type": "c_uint64"},

    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        # "entryTarget": "uint32_t*",
        # "instTargets": "uint32_t**",
        "proto": "LuauRWB_Proto*",
    }


class LuauRWB_NativeContext(LuauRWB_BaseStruct):
    __field_def__ = {
        "gateEntry": {"type": "c_uint64"},
        "gateExit": {"type": "c_uint64"},

        # "fallback": {"type": "LuauRWB_NativeFallBack*LOP__COUNT"},
        # "luauF_table": {"type": "c_uint64*256"},

        "luaV_lessthan": {'type': 'c_uint64'},
        "luaV_lessequal": {'type': 'c_uint64'},
        "luaV_equalval": {'type': 'c_uint64'},
        "luaV_doarith": {'type': 'c_uint64'},
        "luaV_dolen": {'type': 'c_uint64'},
        "luaV_prepareFORN": {'type': 'c_uint64'},
        "luaV_gettable": {'type': 'c_uint64'},
        "luaV_settable": {'type': 'c_uint64'},
        "luaV_getimport": {'type': 'c_uint64'},
        "luaV_concat": {'type': 'c_uint64'},

        "luaH_getn": {'type': 'c_uint64'},
        "luaH_new": {'type': 'c_uint64'},
        "luaH_clone": {'type': 'c_uint64'},
        "luaH_resizearray": {'type': 'c_uint64'},

        "luaC_barriertable": {'type': 'c_uint64'},
        "luaC_barrierf": {'type': 'c_uint64'},
        "luaC_barrierback": {'type': 'c_uint64'},
        "luaC_step": {'type': 'c_uint64'},

        "luaF_close": {'type': 'c_uint64'},

        "luaT_gettm": {'type': 'c_uint64'},
        "luaT_objtypenamestr": {'type': 'c_uint64'},

        "libm_exp": {'type': 'c_uint64'},
        "libm_pow": {'type': 'c_uint64'},
        "libm_fmod": {'type': 'c_uint64'},
        "libm_asin": {'type': 'c_uint64'},
        "libm_sin": {'type': 'c_uint64'},
        "libm_sinh": {'type': 'c_uint64'},
        "libm_acos": {'type': 'c_uint64'},
        "libm_cos": {'type': 'c_uint64'},
        "libm_cosh": {'type': 'c_uint64'},
        "libm_atan": {'type': 'c_uint64'},
        "libm_atan2": {'type': 'c_uint64'},
        "libm_tan": {'type': 'c_uint64'},
        "libm_tanh": {'type': 'c_uint64'},
        "libm_log": {'type': 'c_uint64'},
        "libm_log2": {'type': 'c_uint64'},
        "libm_log10": {'type': 'c_uint64'},
        "libm_ldexp": {'type': 'c_uint64'},
        "libm_round": {'type': 'c_uint64'},
        "libm_frexp": {'type': 'c_uint64'},
        "libm_modf": {'type': 'c_uint64'},

        "forgLoopTableIter": {'type': 'c_uint64'},
        "forgLoopNodeIter": {'type': 'c_uint64'},
        "forgLoopNonTableFallback": {'type': 'c_uint64'},
        "forgPrepXnextFallback": {'type': 'c_uint64'},

        "callProlog": {'type': 'c_uint64'},
        "callEpilogC": {'type': 'c_uint64'},
        "callFallback": {'type': 'c_uint64'},
        "returnFallback":  {'type': 'c_uint64'},

        "fallback":{'type': 'c_uint64 * LOP__COUNT'},
        "luauF_table": {'type': 'c_uint64 * 256'},

    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
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


class LuauRWB_NativeState(LuauRWB_BaseStruct):
    __field_def__ = {
        "codeAllocator": {"type": "LuauRWB_CodeAllocator"},
        "unwindBuilder": {"type": "c_uint32"},
        "gateData": {"type": "c_uint32"},
        "gateDataSize": {"type": "c_uint32"},
        "context": {"type": "LuauRWB_NativeContext"},

    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "unwindBuilder": "std::unique_ptr<UnwindBuilder>",
        "gateData": "uint8_t*",
    }


class LuauRWB_ConstantValue(LuauRWB_BaseUnion):
    __field_def__ = {
        "valueBoolean": {"type": "c_uint32"},
        "valueNumber": {"type": "c_double"},
        "valueString": {"type": "c_uint32"},
        "valueImport": {"type": "c_uint32"},
        "valueTable": {"type": "c_uint32"},
        "valueClosure": {"type": "c_uint32"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _type_enums_ = [i for i in COMPILER_TYPES_MAPPING.values() if isinstance(i, int)]
    _type_string_enums_ = [COMPILER_TYPES_MAPPING[i] for i in COMPILER_TYPES_MAPPING.values() if isinstance(i, int)]


class LuauRWB_ConstantKey(LuauRWB_BaseStruct):
    __field_def__ = {
        "type": {"type": "c_uint32"},
        "value": {"type": "c_uint64"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {}
    _type_enums_ = [i for i in COMPILER_TYPES_MAPPING.values() if isinstance(i, int)]
    _type_string_enums_ = [COMPILER_TYPES_MAPPING[i] for i in COMPILER_TYPES_MAPPING.values() if isinstance(i, int)]



class LuauRWB_Constant(LuauRWB_BaseStruct):
    __field_def__ = {
        "type": {"type": "c_uint32"},
        "stringLength": {"type": "c_uint32"},
        "__anonymous__": {"type": "LuauRWB_ConstantValue"},
    }
    _fields_ = LuauRWB_BaseStruct.create_fields(__field_def__)
    _fields_dict_ = LuauRWB_BaseStruct.create_fields_dict(__field_def__)
    _field_fixups_ = {}
    _type_enums_ = [i for i in COMPILER_TYPES_MAPPING.values() if isinstance(i, int)]
    _type_string_enums_ = [COMPILER_TYPES_MAPPING[i] for i in COMPILER_TYPES_MAPPING.values() if isinstance(i, int)]

    def __init__(self, **kargs):
        super(LuauRWB_Constant, self).__init__(**kargs)
        self.gch = LuauRWB_GCHeader(**kargs)
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
        r, flat = super(LuauRWB_Constant, self).get_dump( word_sz=None)
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
    "TString": LuauRWB_TString,
    "GCObject": LuauRWB_GCObjectUnion,
    "global_State": LuauRWB_global_State,
    "lua_State": LuauRWB_lua_State,
    "TValue": LuauRWB_TValue,
    "Value": LuauRWB_Value,
    "UpVal": LuauRWB_UpVal,
    "CallInfo": LuauRWB_CallInfo,
    "Instruction": ctypes.c_uint32,
    "lua_Page": LuauRWB_lua_Page,
    "LuaNode": LuauRWB_LuaNode,
}

VALID_OBJ_CLS_MAPPING = {
    TSTRING: LuauRWB_TString,
    TTABLE: LuauRWB_Table,
    TCLOSURE: LuauRWB_Closure,
    TUSERDATA: LuauRWB_Udata,
    TTHREAD: LuauRWB_lua_State,
    TPROTO: LuauRWB_Proto,
    TUPVAL: LuauRWB_UpVal,
}

GCO_TT_BMAPPING = {
    TSTRING: LuauRWB_TString,
    TUPVAL: LuauRWB_UpVal,
    TTHREAD: LuauRWB_lua_State,
    TCLOSURE: LuauRWB_Closure,
    TTABLE: LuauRWB_Table,
    TPROTO: LuauRWB_ProtoECB,
    TUSERDATA: LuauRWB_Udata
}
GCO_NAME_BMAPPING = {
    TSTRING: LuauRWB_TString,
    TUPVAL: LuauRWB_UpVal,
    TTHREAD: LuauRWB_lua_State,
    TCLOSURE: LuauRWB_Closure,
    TTABLE: LuauRWB_Table,
    TPROTO: LuauRWB_ProtoECB,
    TUSERDATA: LuauRWB_Udata,
}