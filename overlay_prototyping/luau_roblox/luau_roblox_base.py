
from ..base import *
from luau_roblox_overlay import LUAUR_GCHEADER, TYPES, VALID_MARKS
import struct


class LuauRobloxBase(BaseOverlay):
    _name = "GCHeader"
    _overlay = LUAUR_GCHEADER
    bits32 = get_bits32(_overlay)
    bits64 = get_bits64(_overlay)
    named32 = get_named_array32(_overlay)
    named64 = get_named_array64(_overlay)
    size32 = get_size32(_overlay)
    size64 = get_size64(_overlay)
    types = get_field_types(_overlay)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        v = self.raw_value()
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'ref_addrs':set(), 'is_array':True,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, nbytes, analysis=None, is_32bit=False):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':analysis,
                  "type":cls._name, 'is_32bit': is_32bit}
        fmt = cls.bits32
        sz = cls.struct_size(is_32bit)
        data_unpack = struct.unpack(fmt, nbytes[:sz])
        nfields = cls.named32 if is_32bit else cls.named64
        name_fields(data_unpack, nfields, fields=kargs)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

    @classmethod
    def from_file_obj(cls, fobj, addr, offset=None, analysis=None, is_32bit=False):
        sz = cls.struct_size(is_32bit)
        if offset:
            fobj.seek(offset)
        nbytes = fobj.read(sz+8096)
        tstring = cls.from_bytes(addr, nbytes, analysis, is_32bit=is_32bit)
        setattr(tstring, 'raw_bytes', nbytes)
        return tstring

    @classmethod
    def check_gc_header(cls, nbytes):
        v = LuauRobloxBase.from_bytes(nbytes)
        if v.tt in TYPES and v.marked in VALID_MARKS:
            return True
        return False