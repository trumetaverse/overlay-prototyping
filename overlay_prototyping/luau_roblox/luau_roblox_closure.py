import struct

from .consts import LUAR_ROBLOX_BASE_FUNCS, LUAR_ROBLOX_TYPES, LUAR_ROBLOX_EVENT_NAMES
from .luau_roblox_page import LuauRobloxBase
from .overlay_base import LUAR_CLOSURE_RAW
from ..base import *


class LuauRobloxClosure(LuauRobloxBase):
    _name = "Closure_Raw"
    _overlay = LUAR_CLOSURE_RAW
    bits32 = get_bits32(_overlay)
    bits64 = get_bits64(_overlay)
    named32 = get_named_array32(_overlay)
    named64 = get_named_array64(_overlay)
    size32 = get_size32(_overlay)
    size64 = get_size64(_overlay)
    types = get_field_types(_overlay)
    _TYPE = 0x07

    def __init__(self, **kargs):
        super(LuauRobloxClosure, self).__init__(**kargs)
        self.value = None
        # for k,v in kargs.items():
        #     setattr(self, k, v)

    def probably_valid_string(self):
        return self.value is not None and len(str(self.value)) > 0

    def is_klass_prim(self):
        return True

    def __str__(self):
        return str(getattr(self, 'value', ''))

    # def __repr__(self):
    #     di = self.get_dump()
    #     elems = sorted([[k, v] for k, v in di.items()], key=lambda x:x[0])
    #     lines = []
    #     for k, v in elems:
    #         line = "0x{:08x} {} {} = {}".format(k, v['type'], v['name'], v['value'])
    #         lines.append(line)
    #     return "\n".join(lines)

    def __json__(self):
        return self.get_dump()

    def get_dump(self, unpacked_values=None):
        dump_data = super(LuauRobloxClosure, self).get_dump()
        # data_addr = self.end + 4 if self.is_32bit else self.end + 8
        # dump_data[data_addr] = {'name':'data',
        #       'type': 'char[]', 'value': self.value}
        return dump_data

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        v = self.raw_value()
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'ref_addrs': set(), 'is_array': True,
                                       'is_prim': True, 'value': {},
                                       'addr': self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'" % (self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, nbytes, analysis=None, is_32bit=False):
        if not LuauRobloxBase.check_gc_header(nbytes):
            return None
        kargs = {"addr": addr, "updated": False, 'analysis': analysis,
                 "type": cls._name, 'is_32bit': is_32bit}
        fmt = cls.bits32
        sz = cls.struct_size(is_32bit)
        data_unpack = struct.unpack(fmt, nbytes[:sz])
        nfields = cls.named32 if is_32bit else cls.named64
        name_fields(data_unpack, nfields, fields=kargs)
        pad = kargs['end'] % 8 if kargs['end'] % 8 != 0 else 4 if is_32bit else 8
        # str_len = kargs['end'] - (addr + sz ) + 4 if is_32bit else 8
        # kargs['value'] = "".join([chr(x) for x in nbytes[sz:sz+str_len]])
        # kargs['data'] = kargs['value']
        # kargs['str_len'] = str_len
        # kargs['lua_sz'] = str_len + sz + pad
        # kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

    @classmethod
    def from_file_obj(cls, fobj, addr, offset=None, analysis=None, is_32bit=False):
        sz = cls.struct_size(is_32bit)
        if offset:
            fobj.seek(offset)
        nbytes = fobj.read(sz + 8096)
        tstring = cls.from_bytes(addr, nbytes, analysis, is_32bit=is_32bit)
        setattr(tstring, 'raw_bytes', nbytes)
        return tstring

    def is_string(self):
        return True

    def is_base_func_name(self):
        return str(self.value) in LUAR_ROBLOX_BASE_FUNCS

    def is_event_name(self):
        return str(self.value) in LUAR_ROBLOX_EVENT_NAMES

    def is_base_type_name(self):
        return str(self.value) in LUAR_ROBLOX_TYPES
