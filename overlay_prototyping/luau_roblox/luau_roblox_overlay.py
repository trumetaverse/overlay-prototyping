import struct
from ctypes import *

from .consts import *


class LuauRW_Union(Union):
    _OVERLAY_TYPE_ = 'LuauRW'
    _fields_ = []
    _is_union_ = True
    _fields_dict_ = {}
    _field_fixups_ = {}

    @classmethod
    def create_fields(cls, json_fields):
        return [(k, eval(v['type']), v['bits']) if 'bits' in v else (k, eval(v['type'])) for k, v in
                json_fields.items()]

    @classmethod
    def create_fields_dict(cls, json_fields):
        return dict((k, eval(v['type']), v['bits']) if 'bits' in v else (k, eval(v['type'])) for k, v in
                    json_fields.items())

    def __init__(self, **kargs):
        super().__init__()
        self.initialize_with_kargs(**kargs)

        buf = kargs.get('buf', None)
        if isinstance(buf, bytes):
            fit = min(len(buf), sizeof(self))
            memmove(addressof(self), buf, fit)

        offset = self._offset
        self.initialize_fields(offset, kargs)

    def initialize_fields(self, offset, kargs):
        self._offset = offset
        for name, fld in self._fields_:
            if self.init_required(fld):
                self.initialize_with_kargs(offset=offset, **kargs)

    @classmethod
    def init_required(cls, o):
        return hasattr(o, '_OVERLAY_TYPE_') and o._OVERLAY_TYPE_.find('LuauRW') > -1

    @property
    def addr(self):
        return getattr(self, '_addr') + self.offset

    @property
    def offset(self):
        return getattr(self, '_offset')

    def update_offsets(self, base_offset=0):
        self._offset = base_offset
        offset = self._offset
        for name, field in self._fields_:
            if hasattr(field, '_fields_'):
                ft = field.__name__ if not isinstance(field, str) else field
                fld = getattr(self, name)
                # update word_sz
                if getattr(fld, 'word_sz', 0) is None or getattr(fld, 'word_sz', 0) != self.word_sz:
                    setattr(fld, 'word_sz', self.word_sz)
                if hasattr(fld, 'update_offsets'):
                    fld.update_offsets(base_offset=offset)
                else:
                    setattr(fld, '_offset', offset)
                incr = sizeof(fld)
                if sizeof(field) % self.word_sz != 0:
                    incr += (self.word_sz - sizeof(field) % self.word_sz)
                offset += incr
            else:
                offset += sizeof(field)
        return offset

    @property
    def is_32bit(self):
        return self.word_sz == 4

    @property
    def is_64bit(self):
        return self.word_sz == 8

    def __new__(cls, addr, buf=None, word_sz=4, analysis=None):
        if buf:
            return cls.from_buffer_copy(buf)
        return LittleEndianStructure.__new__(cls)

    def _fields_to_dict(self, obj, addr=None, offset=0, word_sz=4):
        cls = type(obj)
        r = {}
        flat = []
        unions = []
        addr = 0 if addr is None and not hasattr(self, 'addr') else self.addr
        flat.append({"name": '', "value": "UNION_VALUE_START", "addr": addr + offset, 'type': ""})
        for name, field in obj._fields_:
            offset = self.get_offset(name, cls)
            if hasattr(field, '_fields_'):
                _nobj = getattr(self, name)
                _struct_dict, _flat = _nobj.get_dump(offset=offset, addr=addr, word_sz=word_sz)
                y = {"name": name, "value": _struct_dict, "addr": addr + offset, 'type': ft}
                unions.append(y)
                for i in _flat:
                    i['name'] = name + '.' + i['name']

                flat.append({"name": name, "value": "UNION_STRUCT_VALUE_START", "addr": addr, 'type': ft})
                flat = flat + _flat
                flat.append({"name": name, "value": "UNION_STRUCT_VALUE_END", "addr": addr, 'type': ft})

            else:
                ft = field.__name__ if not isinstance(field, str) else field
                x = {"name": name, "value": getattr(obj, name), "addr": addr, 'type': ft}
                unions.append(x)
                flat.append(x)

        r[addr] = unions
        flat.append({"name": '', "value": "UNION_VALUE_END", "addr": addr + offset})
        return r, flat

    def get_offset(self, fld_name, cls=None):
        cls = type(self) if cls is None else cls
        fld = getattr(cls, fld_name, None)
        if fld is not None:
            return getattr(fld, 'offset')
        return None

    def get_dump(self, addr=None, offset=0, word_sz=None):
        word_sz = word_sz if word_sz is not None else self.word_sz if self.word_sz is not None else 4
        r = {}
        flat = []
        cls = type(self)

        if addr is None:
            addr = 0 if not hasattr(self, 'addr') else self.addr
        for name, field in self._fields_:
            offset = self.get_offset(name, cls)
            if hasattr(field, '_fields_'):
                ft = field.__name__ if not isinstance(field, str) else field
                _nobj = getattr(self, name)
                _struct_dict, _flat = _nobj.get_dump(offset=offset, addr=addr, word_sz=word_sz)
                y = {"name": name, "value": _struct_dict, "addr": addr + offset, 'type': ft}
                r[addr + offset] = y
                for i in _flat:
                    i['name'] = name + '.' + i['name']
                flat.append({"name": name, "value": "STRUCT_START", "addr": addr + offset, 'type': ft})
                flat = flat + _flat
            else:
                ft = field.__name__ if not isinstance(field, str) else field
                x = {"name": name, "value": getattr(self, name), "addr": addr + offset, 'type': ft}
                r[addr + offset] = x
                flat.append(x)

        return r, flat

    def __str__(self):
        lines = []
        for line in self.get_dump()[1]:
            fld = self._fields_dict_.get(line['name'])
            line['value_str'] = self.get_str_fmt(fld).format(line['value'])
            l = "{addr:08x} {type} {name} {value_str}".format(**line)
            # if isinstance(line['value'], int):
            #     l = "{addr:08x} {name} {type} {value:08x}".format(**line)
            lines.append(l)
        return "\n".join(lines)

    def __repr__(self):
        return str(self)

    def __json__(self):
        return self.get_dump()[0]

    @property
    def fields(self):
        return self.get_dump()[1]

    @classmethod
    def deserialize(cls, addr, buf, analysis=None, word_sz=4):
        return cls.from_bytes(addr, buf, analysis=analysis, word_sz=word_sz)

    @classmethod
    def from_bytes(cls, addr, buf, analysis=None, word_sz=4):
        f = cls(addr=addr, buf=buf, analysis=analysis, word_sz=word_sz)
        return f

    @classmethod
    def from_file_obj(cls, fobj, addr, offset=None, analysis=None, word_sz=4):
        sz = sizeof(cls)
        if offset:
            fobj.seek(offset)
        nbytes = fobj.read(sz + 8096)
        f = cls(addr=addr, buf=nbytes, analysis=analysis, word_sz=word_sz)
        return f

    @classmethod
    def from_int(cls, addr, value, analysis=None, word_sz=4):
        nbytes = struct.pack("<I", value)
        return cls.from_bytes(addr, nbytes, analysis=analysis, word_sz=word_sz)

    @classmethod
    def get_str_fmt(cls, fld):
        typ = fld._type_ if hasattr(fld, '_type_') else None
        FMTS = {
            'b': "{:02x}", 'B': "{:02x}", "?": "{:02x}",
            'h': "{:04x}", 'H': "{:04x}",
            'i': "{:08x}", 'I': "{:08x}", 'l': "{:08x}", 'L': "{:08x}",
            'q': "{:08x}", 'Q': "{:08x}",
            'e': "{:f}", 'f': "{:f}", 'd': "{:f}", 'L': "{:f}",
        }
        return FMTS.get(typ, "{}")


class LuauRW_Base(LittleEndianStructure):
    _OVERLAY_TYPE_ = 'LuauRW'
    _fields_ = []
    _fields_dict_ = {}
    _is_union_ = False
    _field_fixups_ = {}

    @classmethod
    def create_fields(cls, json_fields):
        return [(k, eval(v['type']), v['bits']) if 'bits' in v else (k, eval(v['type'])) for k, v in
                json_fields.items()]

    @classmethod
    def create_fields_dict(cls, json_fields):
        return dict((k, eval(v['type'])) if 'bits' in v else (k, eval(v['type'])) for k, v in
                    json_fields.items())

    def __init__(self, **kargs):
        super().__init__()
        self.initialize_with_kargs(**kargs)
        buf = kargs.get('buf', None)
        if isinstance(buf, bytes):
            fit = min(len(buf), sizeof(self))
            memmove(addressof(self), buf, fit)

    def initialize_fields(self, offset, **kargs):
        self._offset = offset
        # print("Initializing {}".format(self.__class__.__name__))
        for name, fld in self._fields_:
            if self.init_required(fld):
                # print("Initializing field: {} {}".format(name, fld.__name__))
                _nobj = getattr(self, name)
                _nobj.initialize_with_kargs(offset=offset, **kargs)
                # print(_nobj.__dict__)
                incr = sizeof(fld)
                if sizeof(fld) % self.word_sz != 0:
                    incr += (self.word_sz - sizeof(fld) % self.word_sz)
                offset += incr
            else:
                offset += sizeof(fld)

    def initialize_with_kargs(self, **kargs):
        self._addr = 0
        self.word_sz = 4
        self.__value = None
        self.__value_offset = None
        self._is32b = False
        self._offset = 0
        # print("entering", type(self), self.__dict__)
        # print("given kargs", kargs)
        if 'addr' in kargs:
            self._addr = kargs.get('addr')
        if 'offset' in kargs:
            self._offset = kargs.get('offset')
        accepted_kargs = ['analysis', 'word_sz']

        for k, v in kargs.items():
            if k in accepted_kargs:
                setattr(self, k, v)

        if 'offset' in kargs:
            del kargs['offset']
        self.initialize_fields(self._offset, **kargs)
        # print(self.__dict__)
        # print(self._addr)

    @classmethod
    def init_required(cls, o):
        return hasattr(o, '_OVERLAY_TYPE_') and o._OVERLAY_TYPE_.find('LuauRW') > -1

    @property
    def addr(self):
        return getattr(self, '_addr') + self.offset

    @property
    def offset(self):
        return getattr(self, '_offset')

    @property
    def is_32bit(self):
        return self.word_sz == 4

    @property
    def is_64bit(self):
        return self.word_sz == 8

    def __new__(cls, addr, buf=None, word_sz=4, analysis=None):
        sz = sizeof(cls)
        if buf and sz <= len(buf):
            return cls.from_buffer_copy(buf)
        elif buf is not None:
            return None
        return LittleEndianStructure.__new__(cls)

    def get_offset(self, fld_name, cls=None):
        cls = type(self) if cls is None else cls
        fld = getattr(cls, fld_name, None)
        if fld is not None:
            return getattr(fld, 'offset')
        return None

    def get_dump(self, addr=None, offset=0, word_sz=None):
        if word_sz is None:
            word_sz = 4 if getattr(self, 'word_sz', None) is None else getattr(self, 'word_sz', None)
        cls = type(self)
        r = {}
        flat = []
        if addr is None:
            addr = 0 if not hasattr(self, 'addr') else self.addr
        for name, field in self._fields_:
            offset = self.get_offset(name, cls)
            if hasattr(field, '_fields_'):
                ft = field.__name__ if not isinstance(field, str) else field
                _nobj = getattr(self, name)
                _struct_dict, _flat = _nobj.get_dump(offset=offset, addr=addr, word_sz=word_sz)
                y = {"name": name, "value": _struct_dict, "addr": addr + offset, 'type': ft}
                r[addr + offset] = y
                for i in _flat:
                    i['name'] = name + '.' + i['name']
                flat.append({"name": name, "value": "STRUCT_START", "addr": addr + offset, 'type': ft})
                flat = flat + _flat
                flat.append({"name": name, "value": "STRUCT_END", "addr": addr + offset, 'type': ft})
            else:
                ft = field.__name__ if not isinstance(field, str) else field
                x = {"name": name, "value": getattr(self, name), "addr": addr + offset, 'type': ft}
                r[addr + offset] = x
                flat.append(x)
        return r, flat

    def __str__(self):
        lines = []
        for line in self.get_dump()[1]:
            fld = self._fields_dict_.get(line['name'])
            line['value_str'] = self.get_str_fmt(fld).format(line['value'])
            l = "{addr:08x} {type} {name} {value_str}".format(**line)
            # if isinstance(line['value'], int):
            #     l = "{addr:08x} {name} {type} {value:08x}".format(**line)
            lines.append(l)
        return "\n".join(lines)

    @classmethod
    def get_str_fmt(cls, fld):
        typ = fld._type_ if hasattr(fld, '_type_') else None
        return CTYPE_VALUE_FMTS.get(typ, "{}")

    def __repr__(self):
        return str(self)

    def __json__(self):
        return self.get_dump()[0]

    @property
    def fields(self):
        return self.get_dump()[1]

    def get_value(self):
        return getattr(self, '__value', None)

    def get_value_offset(self):
        return getattr(self, '__value_offset', None)

    @classmethod
    def deserialize(cls, addr, buf, analysis=None, word_sz=4):
        return cls.from_bytes(addr, buf, analysis=analysis, word_sz=word_sz)

    @classmethod
    def from_bytes(cls, addr, buf, analysis=None, word_sz=4):
        f = cls(addr=addr, buf=buf, analysis=analysis, word_sz=word_sz)
        return f

    @classmethod
    def from_file_obj(cls, fobj, addr, offset=None, analysis=None, word_sz=4):
        sz = sizeof(cls)
        if offset:
            fobj.seek(offset)
        nbytes = fobj.read(sz + 8096)
        f = cls(addr=addr, buf=nbytes, analysis=analysis, word_sz=word_sz)
        return f

    @classmethod
    def check_gc_header(cls, buf):
        v = LuauRW_GCHeader.deserialize(0, buf)
        return v.is_valid_gc_header()

    def get_gch(self):
        fld = None
        if hasattr(self, '_cached_gch'):
            return getattr(self, '_cached_gch')
        elif hasattr(self, 'tt') and hasattr(self, 'marked') and hasattr(self, 'gch_padding'):
            fld = self
        elif self.__class__.__name__.find('LuauRW_GCHeader') > -1:
            fld = self
        else:
            for name, fld_type in self._fields_:
                if fld_type.__name__.find('LuauRW_GCHeader') > -1:
                    fld = getattr(self, name)
                    break
        setattr(self, '_cached_gch', fld)
        return fld

    def is_valid_gc_header(self):
        fld = self.get_gch()
        if fld is None:
            return False
        return fld.tt in TYPES and fld.marked in VALID_MARKS and fld.gch_padding == 0

    @classmethod
    def from_int(cls, addr, value, analysis=None, word_sz=4):
        nbytes = struct.pack("<I", value)
        return cls.from_bytes(addr, nbytes, analysis=analysis, word_sz=word_sz)

    def valid_type(self, type_enum):
        fld = self.get_gch()
        return fld is not None and fld.tt == type_enum and fld.marked in VALID_MARKS

    def is_string(self):
        return self.valid_type(TSTRING)

    def is_bool(self):
        return self.tt == TBOOLEAN

    def is_table(self):
        return self.valid_type(TTABLE)

    def is_ud(self):
        return self.valid_type(TUSERDATA)

    def is_function(self):
        return self.valid_type(TFUNCTION)

    def is_number(self):
        return self.tt == TNUMBER

    def is_vector(self):
        return self.tt == TVECTOR

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


# class LuauRW_GCObjectPtr(LuauRW_Base):
#     _OVERLAY_TYPE_ = 'LuauRW'
#     __field_def__ = {
#         "tt": {"type": "c_uint8"},
#         "marked": {"type": "c_uint8"},
#         "memcat": {"type": "c_uint8"},
#         "gch_padding": {"type": "c_uint8"},
#     }
#     _fields_ = LuauRW_Base.create_fields(__field_def__)


class LuauRW_GCHeader(LuauRW_Base):
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)

    def __init__(self, **kargs):
        # print('creating the headers')
        super(LuauRW_GCHeader, self).__init__(**kargs)


class LuauRW_TString(LuauRW_Base):
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)

    def __init__(self, **kargs):
        super(LuauRW_TString, self).__init__(**kargs)
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

    def get_value_offset(self):
        return getattr(self, '__value_offset', None)

    @classmethod
    def deserialize(cls, addr, nbytes, analysis=None, word_sz=4):
        f = cls(addr=addr, analysis=analysis, buf=nbytes, word_sz=word_sz)
        return f

    def get_dump(self, addr=None, offset=0, word_sz=None):
        r, flat = super(LuauRW_TString, self).get_dump(addr, offset)
        vo = self.get_value_offset()
        if vo is not None:
            x = {"name": "data", "value": self.get_value(), "addr": self.addr + self.get_value_offset(),
                 'type': 'char[]'}
            r[x['addr']] = x
            flat.append(x)
        else:
            x = {"name": "data", "value": None, "addr": -1,
                 'type': 'char[]'}
        return r, flat


class LuauRW_ForceAlignment(LuauRW_Union):
    _OVERLAY_TYPE_ = 'LuauRW'
    __field_def__ = {
        "data": {"type": "c_uint8*1"},
        "align1": {"type": "c_double"},
        # "align2": {"type": "c_void_p"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_Value(LuauRW_Union):
    _OVERLAY_TYPE_ = 'LuauRW'
    __field_def__ = {
        "gc": {"type": "c_uint32"},
        "p": {"type": "c_uint32"},
        "n": {"type": "c_double"},
        "b": {"type": "c_int32"},
        "v": {"type": "c_float"},
    }
    _field_fixups_ = {"gc": "GCObject*", "p": "void*"}
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_TValue(LuauRW_Base):
    _OVERLAY_TYPE_ = 'LuauRW'
    __field_def__ = {
        "value": {"type": "LuauRW_Value"},
        "extra": {"type": "c_int32*1"},
        "tt": {"type": "c_uint32"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_Table(LuauRW_Base):
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

        "lastfree_aboundary": {"type": "c_uint32"},
        "metatable": {"type": "c_uint32"},  # Table*
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_LocVar(LuauRW_Base):
    __field_def__ = {
        "varname": {"type": "c_uint32"},  # TString*
        "startpc": {"type": "c_uint8"},
        "endpc": {"type": "c_uint8"},
        "reg": {"type": "c_uint8"},
    }
    _field_fixups_ = {"varname": "TString*"}
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_UnionArrayBoundary(LuauRW_Union):
    __field_def__ = {
        "lastfree": {"type": "c_uint32"},
        "aboundary": {"type": "c_uint32"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


# class LuauRW_Value(LuauRW_Base):
#     __field_def__ = {
#         "gc": {"type": "LuauRW_GCHeader"},
#         "tmcache": {"type": "c_uint8"},
#         "readonly": {"type": "c_uint8"},
#         "safeenv": {"type": "c_uint8"},
#         "lsizenode": {"type": "c_uint8"},
#         "nodemask8": {"type": "c_uint8"},
#         "sizearray": {"type": "c_uint32"},
#         "lastfree_aboundary": {"type": "LuauRW_UnionArrayBoundary"},
#         "metatable": {"type": "c_uint32"},
#         "array": {"type": "c_uint32"},
#         "node": {"type": "c_uint32"},
#         "gclist": {"type": "c_uint32"},
#     }
#     _fields_ = LuauRW_Base.create_fields(__field_def__)
#     _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)

# class LuauRW_Value(LuauRW_Base):
#     __field_def__ = {
#         "gc": {"type": "LuauRW_GCHeader"},
#         "tmcache": {"type": "c_uint8"},
#         "readonly": {"type": "c_uint8"},
#         "safeenv": {"type": "c_uint8"},
#         "lsizenode": {"type": "c_uint8"},
#         "nodemask8": {"type": "c_uint8"},
#         "sizearray": {"type": "c_uint32"},
#         "lastfree_aboundary": {"type": "LuauRW_UnionArrayBoundary"},
#         "metatable": {"type": "c_uint32"},
#         "array": {"type": "c_uint32"},
#         "node": {"type": "c_uint32"},
#         "gclist": {"type": "c_uint32"},
#     }
#     _fields_ = LuauRW_Base.create_fields(__field_def__)
#     _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


# class LuauRW_TTable(LuauRW_Base):
#     __field_def__ = {
#         "gc": {"type": "LuauRW_GCHeader"},
#         "tmcache": {"type": "c_uint8"},
#         "readonly": {"type": "c_uint8"},
#         "safeenv": {"type": "c_uint8"},
#         "lsizenode": {"type": "c_uint8"},
#         "nodemask8": {"type": "c_uint8"},
#         "sizearray": {"type": "c_uint32"},
#         "lastfree_aboundary": {"type": "c_uint32"},
#         "metatable": {"type": "c_uint32"},
#         "array": {"type": "c_uint32"},
#         "node": {"type": "c_uint32"},
#         "gclist": {"type": "c_uint32"},
#     }
#     _fields_ = LuauRW_Base.create_fields(__field_def__)
#     _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_Udata(LuauRW_Base):
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_UpValOpenUnion(LuauRW_Union):
    __field_def__ = {
        "prev": {"type": "c_uint32"},
        "next": {"type": "c_uint32"},
        "thread": {"type": "c_uint32"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "prev": "UpVal*",
        "next": "UpVal*",
        "thread": "UpVal*",
    }


class LuauRW_UpValUnion(LuauRW_Union):
    __field_def__ = {
        "value": {"type": "LuauRW_TValue"},
        "open": {"type": "LuauRW_UpValOpenUnion"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_UpVal(LuauRW_Base):
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_Proto(LuauRW_Base):
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_ProtoECB(LuauRW_Base):
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_ClosureContinuation(LuauRW_Base):
    __field_def__ = {
        "f": {"type": "c_uint32"},
        "cont": {"type": "c_uint32"},
        "debugname": {"type": "c_uint32"},
        "upvals": {"type": "LuauRW_UpVal"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "f": "lua_CFunction",
        "cont": "lua_Continuation",
        "debugname": "c_uint8*",
    }


class LuauRW_ClosureProto(LuauRW_Base):
    __field_def__ = {
        "p": {"type": "c_uint32"},
        "uprefs": {"type": "LuauRW_UpVal"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "p": "Proto*",
    }


class LuauRW_ClosureUnion(LuauRW_Base):
    __field_def__ = {
        "c": {"type": "LuauRW_ClosureContinuation"},
        "uprefs": {"type": "LuauRW_ClosureProto"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_Closure(LuauRW_Base):
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_TKey(LuauRW_Base):
    __field_def__ = {
        "value": {"type": "LuauRW_Value"},
        "extra": {"type": "c_uint32"},
        "tt": {"type": "c_uint32", "bits": 4},
        "next": {"type": "c_uint32", "bits": 28},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_LuaNode(LuauRW_Base):
    __field_def__ = {
        "val": {"type": "LuauRW_TValue"},
        "key": {"type": "LuauRW_TKey"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_CallInfo(LuauRW_Base):
    __field_def__ = {
        "base": {"type": "c_uint32"},
        "func": {"type": "c_uint32"},
        "top": {"type": "c_uint32"},

        "savedpc": {"type": "c_uint32"},
        "nresults": {"type": "c_uint32"},
        "flags": {"type": "c_uint32"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "base": "TValue*",
        "func": "TValue*",
        "top": "TValue*",

        "savedpc": "Instruction*",
    }


class LuauRW_GCStats(LuauRW_Base):
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_lua_ExecutionCallbacks(LuauRW_Base):
    __field_def__ = {
        "context": {"type": "c_uint32"},
        "close": {"type": "c_uint32"},
        "destroy": {"type": "c_int32"},
        "enter": {"type": "c_int32"},
        "setbreakpoint": {"type": "c_int32"},

    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "context": "c_void_p",
        "close": {"type": "void (*close)(lua_State* L)"},
        "destroy": {"type": "void (*destroy)(lua_State* L, Proto* proto)"},
        "enter": {"type": "int (*enter)(lua_State* L, Proto* proto);"},
        "setbreakpoint": {"type": "void (*setbreakpoint)(lua_State* L, Proto* proto, int line)"},
    }


class LuauRW_lua_Callbacks(LuauRW_Base):
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)
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


class LuauRW_stringtable(LuauRW_Base):
    __field_def__ = {
        "hash": {"type": "c_uint32"},
        "nuse": {"type": "c_uint32"},
        "size": {"type": "c_int32"},
        "enter": {"type": "c_int32"},

    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)
    _field_fixups_ = {
        "hash": "TString**",
    }


class LuauRW_lua_State(LuauRW_Base):
    __field_def__ = {
        "tt": {"type": "c_uint8"},
        "marked": {"type": "c_uint8"},
        "memcat": {"type": "c_uint8"},
        "gch_padding": {"type": "c_uint8"},

        "status": {"type": "c_uint8"},
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_global_State(LuauRW_Base):
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
        "registry": {"type": "LuauRW_TValue"},
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_GCObjectUnion(LuauRW_Union):
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)


class LuauRW_lua_Page(LuauRW_Base):
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
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)
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


class LuauRW_LG(LuauRW_Base):
    __field_def__ = {
        "l": {"type": "LuauRW_lua_State"},
        "g": {"type": "LuauRW_global_State"},
    }
    _fields_ = LuauRW_Base.create_fields(__field_def__)
    _fields_dict_ = LuauRW_Base.create_fields_dict(__field_def__)
