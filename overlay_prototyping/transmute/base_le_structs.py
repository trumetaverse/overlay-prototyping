import struct
from ctypes import *

from .consts import *


class Transmute_BaseLES(LittleEndianStructure):
    _OVERLAY_TYPE_ = 'Transmute_BaseLES'
    _fields_ = []
    _fields_dict_ = {}
    _is_union_ = False
    _field_fixups_ = {}
    _gco_ = False
    _tt_ = None
    _gc_header_cls_ = None
    _type_registry_ = None
    _init_required_ = False
    _has_sanity_check_ = False

    @classmethod
    def get_field_cls(cls, name):
        type_registry = cls._type_registry_
        if type_registry is not None and name in cls._field_fixups_:
            alias = cls._field_fixups_[name]
            fld_cls = type_registry.get_type(alias)
            if fld_cls is not None:
                return alias, fld_cls
        return None, cls._fields_dict_[name]

    @classmethod
    def create_fields(cls, json_fields):
        return [(k, eval(v['type']), v['bits']) if 'bits' in v else (k, eval(v['type'])) for k, v in
                json_fields.items()]

    @classmethod
    def create_fields_dict(cls, json_fields):
        return dict((k, eval(v['type'])) if 'bits' in v else (k, eval(v['type'])) for k, v in
                    json_fields.items())

    def __init__(self, **kargs):
        self._offset = 0
        self.references = {}
        super(LittleEndianStructure, self).__init__()
        buf = kargs.get('buf', None)
        # if isinstance(buf, bytes):
        #     fit = min(len(buf), sizeof(self))
        #     memmove(addressof(self), buf, fit)
        self.initialize_with_kargs(**kargs)


    def initialize_fields(self, offset, **kargs):
        self._offset = offset
        if 'word_sz' not in kargs:
            kargs['word_sz'] = 4

        buf = kargs.get('buf', None)
        nkargs = {k:v for k,v in kargs.items() if k != 'buf'}
        for x in self._fields_:
            name, fld = x[:2]
            if self.init_required(fld):
                offset = self.get_offset(name)
                _nobj = getattr(self, name)
                if hasattr(fld, '_OVERLAY_TYPE_'):
                    sz = sizeof(fld)
                    nkargs['addr'] = self.addr + offset
                    # print("transmute_struct.initialize_fields ", type(self), name, type(fld), nkargs)
                    nbuf = None if buf is None or len(buf) < offset + sz else buf[offset:]
                    _nobj.initialize_with_kargs(buf=nbuf, **nkargs)

    def initialize_with_kargs(self, **kargs):
        self._addr = 0
        self.word_sz = 4
        self.__value = None
        self.__value_offset = None
        self._is32b = False
        self._offset = 0
        if 'addr' in kargs:
            self._addr = kargs.get('addr')
        if 'offset' in kargs:
            self._offset = kargs.get('offset')
        accepted_kargs = ['analysis', 'word_sz']

        for k, v in kargs.items():
            if k in accepted_kargs:
                setattr(self, k, v)

        buf = kargs.get('buf', None)
        # if isinstance(buf, bytes):
        #     fit = min(len(buf), sizeof(self))
        #     memmove(addressof(self), buf, fit)

        nkargs = kargs.copy()
        if 'offset' in nkargs:
            del nkargs['offset']
        # if 'buf' in kargs:
        #     _nkargs = kargs.copy()
        #     kargs = _nkargs
        #     del kargs['buf']
        self.initialize_fields(self._offset, **nkargs)
        # print("transmute_struct.initialize_with_kargs end ", type(self), nkargs, 'my_vals', self.__dict__)
        self.do_fixups(**kargs)

    @classmethod
    def init_required(cls, o):
        return cls._init_required_

    @property
    def addr(self):
        return getattr(self, '_addr', 0)

    # @property
    # def offset(self):
    #     return getattr(self, '_offset')

    @property
    def is_32bit(self):
        return self.word_sz == 4

    @property
    def is_64bit(self):
        return self.word_sz == 8

    def __new__(cls, addr, buf=None, word_sz=4, analysis=None):
        sz = sizeof(cls)
        if buf is None and analysis is not None:
            buf = analysis.read_vaddr(addr, sizeof(cls))
        if buf and sz <= len(buf):
            v = cls.from_buffer_copy(buf)
            # v.initialize_with_kargs(addr=addr, buf=buf, word_sz=word_sz, analysis=analysis)
            return v
        elif buf is not None:
            return None
        return LittleEndianStructure.__new__(cls)

    @classmethod
    def get_offset(cls, fld_name, tcls=None):
        tcls = cls if tcls is None else tcls
        cls_fld = getattr(tcls, fld_name, None)
        return getattr(cls_fld, 'offset', None)

    def get_alias(self, name):
        if name in self._field_fixups_:
            return self._field_fixups_[name]
        return None

    def get_typestr_for_dump(self, name):
        field = self._fields_dict_.get(name, None)
        alias = self.get_alias(name)
        ft = field.__name__ if not isinstance(field, str) else field
        if alias is None:
            return str(ft)
        return "{} as {}".format(alias, ft)

    @classmethod
    def is_field_array(cls, name):
        _ncls = cls._fields_dict_[name]
        if hasattr(_ncls, '__class__') and str(_ncls.__class__).find('ArrayType') > 0:
            return True
        elif hasattr(_ncls, '__name__') and str(_ncls.__name__).find('_Array_') > 0:
            return True
        return False

    def get_dump(self, word_sz=None, addr=0):
        if word_sz is None:
            word_sz = 4 if getattr(self, 'word_sz', None) is None else getattr(self, 'word_sz', None)
        cls = type(self)
        r = {}
        flat = []

        addr = self.addr if self.addr is not None and self.addr > 0 else addr

        for x in self._fields_:
            name, field = x[:2]
            is_array = self.is_field_array(name)
            offset = self.get_offset(name, cls)
            ft = self.get_typestr_for_dump(name)
            fmt = self.get_str_fmt(name)
            if hasattr(field, '_fields_') and getattr(self, '_is_union_', False):
                _nobj = getattr(self, name)
                _struct_dict, _flat = _nobj.get_dump( word_sz=word_sz, addr=addr+offset)
                y = {"name": name, "value": _struct_dict, "addr": addr + offset, 'type': ft, 'offset': offset,
                     "fmt": fmt, "is_array": is_array}
                r[addr + offset] = y
                for i in _flat:
                    i['name'] = name + '.' + i['name']
                flat.append(
                    {"name": name, "value": "STRUCT_START", "addr": addr + offset, 'type': ft, 'offset': offset,
                     "fmt": fmt, "is_array": is_array})
                flat = flat + _flat
                flat.append({"name": name, "value": "STRUCT_END", "addr": addr + offset, 'type': ft, 'offset': offset,
                             "fmt": fmt, "is_array": is_array})
            elif hasattr(field, '_fields_'):
                _nobj = getattr(self, name)
                _struct_dict, _flat = _nobj.get_dump( word_sz=word_sz, addr=addr+offset)
                y = {"name": name, "value": _struct_dict, "addr": addr + offset, 'type': ft, 'offset': offset,
                     "fmt": fmt, "is_array": is_array}
                r[addr + offset] = y
                for i in _flat:
                    i['name'] = name + '.' + i['name']
                flat.append(
                    {"name": name, "value": "UNION_START", "addr": addr + offset, 'type': ft, 'offset': offset,
                     "fmt": fmt, "is_array": is_array})
                flat = flat + _flat
                flat.append({"name": name, "value": "UNION_END", "addr": addr + offset, 'type': ft, 'offset': offset,
                             "fmt": fmt, "is_array": is_array})
            else:
                # ft = field.__name__ if not isinstance(field, str) else field
                x = {"name": name, "value": getattr(self, name), "addr": addr + offset, 'type': ft, 'offset': offset,
                     "fmt": fmt, "is_array": is_array}
                r[addr + offset] = x
                flat.append(x)
        return r, flat

    def __str__(self):
        lines = []
        for line in self.get_dump()[1]:
            fmt = line['fmt']
            if line['is_array']:
                line['value_str'] = "[{}]".format(', '.join([fmt.format(i) for i in line['value']]))
            else:
                line['value_str'] = fmt.format(line['value'])
            l = "{addr:08x} {type} {name} {value_str}".format(**line)
            lines.append(l)
        return "\n".join(lines)

    @classmethod
    def get_str_fmt(cls, name):
        fld = cls._fields_dict_[name] if name in cls._fields_dict_ else None
        if cls.is_field_array(name):
            typ = fld._type_._type_ if hasattr(fld, '_type_') and hasattr(fld._type_, "_type_") else None
        else:
            typ = fld._type_ if hasattr(fld, '_type_') else None
        fmt = CTYPE_VALUE_FMTS.get(typ, "{}")
        return fmt

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

    def has_value(self):
        return hasattr(self, '__value') and not getattr(self, '__value', None) is None

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
    def from_analysis(cls, addr, analysis, word_size=4, safe_load=True):
        buf = analysis.read_vaddr(addr, sizeof(cls))
        if safe_load and (buf is None or len(buf) != sizeof(cls)):
            raise BaseException("Failed to read bytes for {}".format(str(type(cls))))
        return cls.from_bytes(addr, buf, analysis=analysis, word_sz=word_size)

    @classmethod
    def check_gc_header(cls, buf):
        if cls._gc_header_cls_ is None:
            return False
        v = cls._gc_header_cls_.deserialize(0, buf)
        return v.is_valid_gc_header()

    @classmethod
    def is_gco(cls):
        return cls._gc_header_cls_ is not None and cls._gco_

    def get_gch(self):
        if not self._gco_ or self._gc_header_cls_ is None:
            return None
        fld = None
        if hasattr(self, '_cached_gch'):
            return getattr(self, '_cached_gch')
        # TODO implement GCH parsing code here
        setattr(self, '_cached_gch', fld)
        return fld

    @property
    def gco(self):
        return self._gco_

    @classmethod
    def has_gc_header(cls):
        return cls.gco and cls._gc_header_cls_ is not None

    def is_valid_gc_header(self):
        return False

    @classmethod
    def is_field_array(cls, name):
        _ncls = cls._fields_dict_[name]
        if hasattr(_ncls, '__class__') and str(_ncls.__class__).find('ArrayType') > 0:
            return True
        elif hasattr(_ncls, '__name__') and str(_ncls.__name__).find('_Array_') > 0:
            return True
        return False

    @classmethod
    def from_int(cls, addr, value, analysis=None, word_sz=4):
        nbytes = struct.pack("<I", value)
        return cls.from_bytes(addr, nbytes, analysis=analysis, word_sz=word_sz)

    def valid_type(self, type_enum):
        return False

    def is_prim(self):
        return False

    def has_sanity_check(self):
        return self._has_sanity_check_

    def sanity_check(self):
        return not self._has_sanity_check_

    def do_fixups(self, **kargs):
        pass

    def get_total_size(self):
        return sizeof(self)

    def get_next_gco(self):
        return None
