# LuauRobloxBinding
import ctypes
from ..base import BaseException

class Binding(object):

    def set_info(self, name, fld_cls, alias):
        setattr(self, "___cls", fld_cls)
        setattr(self, "___alias", alias)
        setattr(self, "___name", name)

        setattr(self, "___fields", )

    def add_type_field(self, name, fld_cls, alias, offset):
        setattr(self, "___cls_{}".format(name), fld_cls)
        setattr(self, "___alias_{}".format(name), alias)
        setattr(self, "___offset_{}".format(name), offset)

    def get_fld_alias(self, name):
        alias = getattr(self, '___alias_{}'.format(name), None)
        return alias

    def get_fld_cls(self, name):
        alias = getattr(self, '___cls_{}'.format(name), None)
        return alias

    def get_fld_offset(self, name):
        alias = getattr(self, '___offset_{}'.format(name), None)
        return alias


        # for name, field in self._fields_:
        #     offset = self.get_offset(name, cls)
        #     if hasattr(field, '_fields_'):
        #         ft = field.__name__ if not isinstance(field, str) else field
        #         _nobj = getattr(self, name)
        #         _struct_dict, _flat = _nobj.get_dump(offset=offset, addr=addr, word_sz=word_sz)
        #         y = {"name": name, "value": _struct_dict, "addr": addr + offset, 'type': ft, 'offset': offset}
        #         r[addr + offset] = y
        #         for i in _flat:
        #             i['name'] = name + '.' + i['name']
        #         flat.append({"name": name, "value": "STRUCT_START", "addr": addr + offset, 'type': ft, 'offset': offset})
        #         flat = flat + _flat
        #         flat.append({"name": name, "value": "STRUCT_END", "addr": addr + offset, 'type': ft, 'offset': offset})
        #     else:
        #         ft = field.__name__ if not isinstance(field, str) else field
        #         x = {"name": name, "value": getattr(self, name), "addr": addr + offset, 'type': ft, 'offset': offset}
        #         r[addr + offset] = x
        #         flat.append(x)
    def __init__(self, name, ctypes_overlay_value, analysis=None, fixup=False, little_endian=True, word_sz=4):
        self.analysis = analysis
        self.___name = name
        self.___addr = ctypes_overlay_value.addr
        alias, fld_cls = ctypes_overlay_value.get_field_cls(name)
        self.___alias = alias
        self.___cls = fld_cls

        for name, field in self._fields_:
            offset = self.get_offset(name, fld_cls)
            self.add_type_field(name, fld_cls, alias, offset)
            name = obj_json.get('name')
            value = obj_json.get('value')
            alias, fld_cls = ctypes_overlay_value.get_field_cls(name)
            offset = ctypes_overlay_value.get_offset(name)
            fld_value = getattr(ctypes_overlay_value, 'name')

            _bv = value
            if fixup and alias is not None:
                self.add_type_field(name, fld_cls, alias, offset)
                self.handle_fixup_bv(ctypes_overlay_value, name, alias, value, offset, fixup=fixup, little_endian=little_endian, word_sz=word_sz)
            elif isinstance(value, dict):
                self.add_type_field(name, fld_cls, alias, offset)
                self.handle_struct_bv(ctypes_overlay_value, name, value, offset, fixup=fixup, little_endian=little_endian, word_sz=word_sz)
            elif isinstance(value, list) and hasattr(fld_value, '_OVERLAY_TYPE_') and getattr(fld_value, 'is_union', True)
                self.add_type_field(name, fld_cls, alias, offset)
                self.handle_union_bv(ctypes_overlay_value, name, value, offset, fixup=fixup, little_endian=little_endian, word_sz=word_sz)
            else:
                self.add_type_field(name, fld_cls, alias, offset)
                setattr(self, name, _bv)

    def handle_union_bv(self, ctypes_overlay_value,  name, value, offset, fixup=False, little_endian=True, word_sz=4):
        if name.find('__anonymous__') > -1:
            # for each field get the name and add it to this bv
            name = obj_json.get('name')
            value = obj_json.get('value')
            alias, fld_cls = ctypes_overlay_value.get_field_cls(name)
            offset = ctypes_overlay_value.get_offset(name)
            fld_value = getattr(ctypes_overlay_value, 'name')
            for v in value:
                name = obj_json.get('name')
                value = obj_json.get('value')
                alias, fld_cls = ctypes_overlay_value.get_field_cls(name)
                offset = ctypes_overlay_value.get_offset(name)
                fld_value = getattr(ctypes_overlay_value, 'name')

                if fixup and alias is not None:
                    self.add_type_field(name, fld_cls, alias, offset)
                    self.handle_fixup_bv(ctypes_overlay_value, name, alias, value, offset, fixup=fixup,
                                         little_endian=little_endian, word_sz=word_sz)
                elif isinstance(value, dict):
                    self.add_type_field(name, fld_cls, alias, offset)
                    self.handle_struct_bv(ctypes_overlay_value, name, value, offset, fixup=fixup,
                                          little_endian=little_endian, word_sz=word_sz)
                elif isinstance(value, list) and hasattr(fld_value, '_OVERLAY_TYPE_'):
                    self.add_type_field(name, fld_cls, alias, offset)
                    self.handle_union_bv(ctypes_overlay_value, name, value, offset, fixup=fixup,
                                         little_endian=little_endian, word_sz=word_sz)
                else:
                    self.add_type_field(name, fld_cls, alias, offset)
                    setattr(self, name, _bv)

        else:
            fld_value = getattr(ctypes_overlay_value, 'name')
            _bv = Binding(fld_value, analysis=self.analysis, fixup=fixup, little_endian=little_endian, word_sz=word_sz)


    def handle_struct_bv(self,  ctypes_overlay_value, name, alias, value, offset, fixup=False, little_endian=True, word_sz=4):
        fld_value = getattr(ctypes_overlay_value, 'name')
        _bv = Binding(fld_value, analysis=self.analysis, fixup=fixup, little_endian=little_endian, word_sz=word_sz)

    def handle_fixup_bv(self, name, value, offset):
        num_ptrs = sum([1 if i == '*' else 0 for i in alias])
        o_addr = addr + offset
        while num_ptrs > 0:
            if num_ptrs >= 2:
                o_addr = analysis.double_deref_address(o_addr, word_sz, little_endian)
                num_ptrs += -2
            else:
                o_addr = analysis.deref_address(o_addr, word_sz, little_endian)
                num_ptrs += -1
        fld_value = fld_cls.from_analysis(o_addr, analysis, word_sz)
        _bv = Binding(fld_value, analysis=analysis, fixup=fixup, little_endian=little_endian, word_sz=word_sz)


class LuauRB(object):
    _name = "Invalid"
    _cls_overlay = None
    _cls_fields = None
    _cls_size = None

    @property
    def static_size(cls):
        return ctypes.sizeof(cls._cls_overlay)

    @property
    def binding(self):
        return self._binding

    def __init__(self, addr, analysis=None, buf=None, word_sz=None, safe_ops=True, fix_up=False):
        self.safe_ops = safe_ops
        self.analysis = analysis
        self.addr = addr
        self._binding = None
        self.word_sz = None

        if buf is None:
            buf = analysis.read_vaddr(addr, ctypes.sizeof(self._cls_overlay))
            if len(buf) != self.static_size:
                raise BaseException("Not enough data to create struct")
        self._obj = self._cls_overlay(addr=addr, buf=buf, word_sz=word_sz, analysis=analysis)
        self._binding = Binding(self._cls_overlay, addr)

        for fld in self._obj:
            setattr

        # here we iterate over the _fix_up_ fields to add them to the binding
