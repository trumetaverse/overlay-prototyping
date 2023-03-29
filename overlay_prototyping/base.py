import re, struct

import binascii

lendian_s2d = lambda sbytes: struct.unpack("<I", binascii.unhexlify(sbytes))[0]
lendian_s2x = lambda sbytes: hex(struct.unpack("<I", binascii.unhexlify(sbytes))[0])

BITS32 = 0
BITS64 = 1
TYPES = 2
NAMES = 3


def name_fields(unpacked, names, fields={}):
    pos = 0
    end = len(unpacked) if len(unpacked) < len(names) \
        else len(names)
    while pos < end:
        name = names[pos]
        fields[name] = unpacked[pos]
        pos += 1
    return fields


def print_overlay_offsets32(overlay_definition, values, base_off=0):
    pos = 0
    fmt = "%s %s %s = %s"
    d = []
    types = get_field_types(overlay_definition)
    names = get_named_array32(overlay_definition)
    sizes = get_field_sizes32(overlay_definition)
    while pos < len(names):
        name = names[pos]
        sz = struct.calcsize(sizes[pos])
        value = ("0x%0" + "%dx" % (sz * 2)) % values[pos]
        offset = hex(base_off)
        type_ = types[pos]
        d.append((fmt % (offset, type_, name, value)))
        pos += 1
        base_off += struct.calcsize(sizes[pos - 1])
    # print "\n".join(d)
    return "\n".join(d)


def get_overlay_offsets64(overlay_definition, values=None, base_off=0):
    pos = 0
    fmt = "%s %s %s = %s"
    d = []
    types = get_field_types(overlay_definition)
    names = get_named_array64(overlay_definition)
    sizes = get_field_sizes64(overlay_definition)
    if values is None:
        values = ['' for _ in range(0, len(names))]

    overlay_info = {}
    offset = 0
    while pos < len(names):
        name = names[pos]
        sz = struct.calcsize(sizes[pos])
        type_ = types[pos]
        value = ''
        if pos < len(values):
            value = values[pos]
        overlay_info[base_off + offset] = {'name': name,
                                           'type': type_, 'value': value}
        pos += 1
        offset += struct.calcsize(sizes[pos - 1])
    return overlay_info


def get_overlay_offsets32(overlay_definition, values=None, base_off=0):
    pos = 0
    fmt = "%s %s %s = %s"
    d = []
    types = get_field_types(overlay_definition)
    names = get_named_array32(overlay_definition)
    sizes = get_field_sizes32(overlay_definition)
    if values is None:
        values = ['' for _ in range(0, len(names))]

    overlay_info = {}
    offset = 0
    while pos < len(names):
        name = names[pos]
        sz = struct.calcsize(sizes[pos])
        type_ = types[pos]
        value = ''
        if pos < len(values):
            value = values[pos]
        overlay_info[base_off + offset] = {'name': name,
                                           'type': type_, 'value': value}

        pos += 1
        offset += struct.calcsize(sizes[pos - 1])
    return overlay_info


def print_overlay_offsets64(overlay_definition, values, base_off=0):
    pos = 0
    fmt = "%s %s = %s @ %s"
    types = get_field_types(overlay_definition)
    names = get_named_array64(overlay_definition)
    sizes = get_field_sizes64(overlay_definition)
    d = []
    while pos < len(overlay_definition):
        name = names[pos]
        value = hex(values[pos])
        offset = hex(base_off)
        type_ = types[pos]
        d.append((fmt % (offset, type_, name, value)))
        pos += 1
        base_off += struct.calcsize(sizes[pos - 1])
    return "\n".join(d)


def get_named_types_tup_list(overlay_definition):
    field_types = get_field_types(overlay_definition)
    field_names = get_named_array32(overlay_definition)
    res = []
    for pos in range(0, len(field_names)):
        res.append((field_names[pos], field_types[pos]))
    return res


def get_named_types_dict(overlay_definition):
    field_types = get_field_types(overlay_definition)
    field_names = get_named_array32(overlay_definition)
    res = {}
    for pos in range(0, len(field_names)):
        res[field_names[pos]] = field_types[pos]
    return res


def contains_digits(d):
    _digits = re.compile(r'\d')
    return bool(_digits.search(d))


def get_bits32(overlay_definition):
    bits32 = [i[BITS32] for i in overlay_definition]
    return "".join(bits32)


def get_bits64(overlay_definition):
    bits64 = [i[BITS64] for i in overlay_definition]
    return "".join(bits64)


def get_field_sizes64(overlay_definition):
    types = []
    for t in overlay_definition:
        num = 1
        f = t[BITS64]
        if contains_digits(t[BITS64]):
            # print t
            digits = [i for i in t[BITS64] if i.isdigit()]
            f = "".join(t[BITS64][len(digits):])
            # print num
            num = int("".join(digits))
        if num == 1:
            types.append(f)
        else:
            types += [f for i in range(0, num)]
    return types


def get_field_sizes32(overlay_definition):
    types = []
    for t in overlay_definition:
        num = 1
        f = t[BITS32]
        if contains_digits(t[BITS32]):
            # print t
            digits = [i for i in t[BITS32] if i.isdigit()]
            f = "".join(t[BITS32][len(digits):])
            # print num
            num = int("".join(digits))
        if num == 1:
            types.append(f)
        else:
            types += [f for i in range(0, num)]
    return types


def get_field_types(overlay_definition):
    types = []
    for t in overlay_definition:
        num = 1
        if contains_digits(t[BITS32]):
            # print t
            digits = [i for i in t[BITS32] if i.isdigit()]
            # print num
            num = int("".join(digits))
        if num == 1:
            types.append(t[TYPES])
        else:
            types += [(t[TYPES]) for i in range(0, num)]
    return types


def get_size64(overlay_definition):
    size64 = struct.calcsize(get_bits64(overlay_definition))
    return size64


def get_size32(overlay_definition):
    size32 = struct.calcsize(get_bits32(overlay_definition))
    return size32


def get_named_array32(overlay_definition):
    names = []
    for t in overlay_definition:
        num = 1
        if contains_digits(t[BITS32]):
            # print t
            digits = [i for i in t[BITS32] if i.isdigit()]
            # print num
            num = int("".join(digits))
        if num == 1:
            names.append(t[NAMES])
        else:
            names += [(t[NAMES] + "_%d") % i for i in range(0, num)]
    return names


def get_named_array64(overlay_definition):
    names = []
    for t in overlay_definition:
        num = 1
        if contains_digits(t[BITS64]):
            # print t
            digits = [i for i in t[BITS64] if i.isdigit()]
            # print num
            num = int("".join(digits))
        if num == 1:
            names.append(t[NAMES])
        else:
            names += [(t[NAMES] + "_%d") % i for i in range(0, num)]
    return names


class BaseException(Exception):
    pass


def overlay_factory(name, overlay_def, is_win):
    return BaseOverlay.create_overlay(name, overlay_def, is_win)


class BaseOverlay(object):
    is_win = False
    _name = "Base"  # KLASS_TYPE
    _overlay = None
    bits32 = 0  # get_bits32(KLASS_TYPE)
    bits64 = 0  # get_bits64(KLASS_TYPE)
    named32 = "Base32"  # get_named_array32(KLASS_TYPE)
    named64 = "Base64"  # get_named_array64(KLASS_TYPE)
    size32 = 0  # get_size32(KLASS_TYPE)
    size64 = 0  # get_size64(KLASS_TYPE)
    types = []  # get_field_types(KLASS_TYPE)

    def __init__(self, **kargs):
        for k, v in kargs.items():
            setattr(self, k, v)

        self.overlay_info = None
        self.is_32bit = False
        self.base_addr = 0
        setattr(self, 'is_32bit', kargs.get('is_32bit', True))
        if self.is_32bit:
            self.word_sz = 4

        setattr(self, 'overlay_info', None)

    def __getstate__(self):
        # analysis = getattr(self, 'analysis', None)
        # setattr(self, 'analysis', None)
        # print ("Pickling: %s"%str(self))
        # odict = self.__dict__.copy()#copy.deepcopy(self.__dict__)
        # print ("Done with the copy: %s"%str(self))
        # setattr(self, 'analysis', analysis)
        return self.__dict__

    def set_analysis(self, env):
        setattr(self, 'analysis', env)

    def __setstate__(self, _dict):
        self.__dict__.update(_dict)

    def is_updated(self, force_update=False):
        if getattr(self, 'updated', False) or force_update:
            return True
        return False

    def get_addr(self):
        return getattr(self, 'addr')

    def get_overlay_info_addr(self, addr, force_update=False):
        if not hasattr(self, 'overlay_info') or \
                force_update or \
                getattr(self, 'overlay_info', None) is None:
            self.get_overlay_info(force_update)

        res = {'name': None, 'type': None}
        if self.overlay_info and addr in self.overlay_info:
            res[addr]['name'] = res[addr]['type']
        return res

    def get_overlay_info(self, force_update=False):
        if hasattr(self, 'overlay_info') and \
                not force_update and \
                not getattr(self, 'overlay_info', None) is None:
            return getattr(self, 'overlay_info')

        addr = getattr(self, 'addr', None)
        overlay = getattr(self, '_overlay', None)
        analysis = getattr(self, 'analysis', None)
        try:
            if analysis and analysis.is_32bit:
                self.overlay_info = get_overlay_offsets32(overlay,
                                                          addr)
            elif analysis and not analysis.is_32bit:
                self.overlay_info = get_overlay_offsets64(overlay,
                                                          addr)
        except:
            import traceback
            traceback.print_exc()
        return self.overlay_info

    def __json__(self):
        return self.get_dump()

    @classmethod
    def align_pad(cls, addr, align=8):
        return (align - (addr % align)) % align

    # TODO highly inappropriate to do the whole classmethod vs. instance method here
    # trying to account for windows
    @classmethod
    def header_size32(cls):
        sz = cls.size32
        if cls._name.find("Klass") > -1:
            sz = cls.size32 - (BaseOverlay.is_win * 4)
        return sz + cls.align_pad(sz)

    @classmethod
    def header_size64(cls):
        sz = cls.size64
        return sz + cls.align_pad(sz)

    def header_size(self):
        sz = self.size()
        return sz + self.align_pad(sz)

    def print_dump(self):
        print(self.get_dump())

    def update_fields(self, force_update=False):
        print("Error: %s does not implement this method" % getattr(self, '_name'))
        raise NotImplementedError

    def parse_class_fields(self, force_update=False):
        print("Error: %s does not implement this method" % getattr(self, '_name'))
        raise NotImplementedError

    def raw_value(self):
        print("Error: %s does not implement this method" % getattr(self, '_name'))
        raise NotImplementedError

    def agg_size(self):
        print("Error: %s does not implement this method" % getattr(self, '_name'))
        raise NotImplementedError

    def size_aligned(self):
        sz = self.size()
        return sz + self.align_pad(sz)

    def size(self):
        is_32bit = getattr(self, "is_32bit")
        if is_32bit:
            return getattr(self, 'size32')
        else:
            return getattr(self, 'size64')

    @classmethod
    def struct_size(cls, is_32bit=False):
        if is_32bit:
            return getattr(cls, 'size32')
        else:
            return getattr(cls, 'size64')

    @classmethod
    def from_analysis(cls, addr, analysis, **kargs):
        sz = cls.size32 if analysis.is_32bit else \
            cls.size64
        if addr == 0 or not analysis.is_valid_addr(addr):
            return None
        nbytes = analysis.read(addr, sz)
        if nbytes is None:
            # print ("Error: failed to read %d bytes @ 0x%08x"%(sz, addr))
            return None
        elif len(nbytes) != sz:
            # print ("Error: failed to read %d bytes @ 0x%08x"%(sz, addr))
            return None
        return cls.from_bytes(addr, nbytes, analysis, **kargs)

    @classmethod
    def from_file_obj(cls, fobj, addr, offset=None, is_32bit=False):
        sz = cls.struct_size(is_32bit)
        if offset:
            fobj.seek(offset)
        nbytes = fobj.read(sz)
        return cls.from_bytes(addr, nbytes, analysis=None, is_32bit=is_32bit)

    @classmethod
    def reset_overlay(cls, overlay_definition):
        cls._overlay = overlay_definition
        cls.bits32 = get_bits32(overlay_definition)
        cls.bits64 = get_bits64(overlay_definition)
        cls.named32 = get_named_array32(overlay_definition)
        cls.named64 = get_named_array64(overlay_definition)
        cls.size32 = get_size32(overlay_definition)
        cls.size64 = get_size64(overlay_definition)
        cls.types = get_field_types(overlay_definition)

    @classmethod
    def create_overlay(cls, name, overlay_definition, is_win=True):
        attrs = {
            '_overlay': overlay_definition,
            'bits32': get_bits32(overlay_definition),
            'bits64': get_bits64(overlay_definition),
            'named32': get_named_array32(overlay_definition),
            'named64': get_named_array64(overlay_definition),
            'size32': get_size32(overlay_definition),
            'size64': get_size64(overlay_definition),
            'types': get_field_types(overlay_definition),
            'is_win': is_win
        }
        new_cls = type(name, (BaseOverlay,), attrs)
        new_cls.is_win = is_win
        return new_cls

    def get_unpacked_values(self):
        return getattr(self, 'unpacked_values', None)

    def get_dump(self):
        unpacked_values = self.get_unpacked_values()
        addr = getattr(self, 'addr', None)
        overlay = getattr(self, '_overlay', None)
        analysis = getattr(self, 'analysis', None)

        dump_data = {}
        if self.is_32bit:
            dump_data = get_overlay_offsets32(overlay,
                                              values=unpacked_values, base_off=addr)
        else:
            dump_data = get_overlay_offsets64(overlay,
                                              values=unpacked_values, base_off=addr)
        return dump_data

    def __repr__(self):
        dump_data = self.get_dump()
        for k in dump_data:
            _value = dump_data[k]['value']
            value = '"{}"'.format(str(_value))
            if isinstance(_value, int):
                t = dump_data[k]['type']
                fmt = "0x{:08x}"
                if t.find('32') > -1 or t.find('*') > -1:
                    fmt = "0x{:08x}"
                elif t.find('8') > -1:
                    fmt = "0x{:02x}"
                elif t.find('16') > -1:
                    fmt = "0x{:04x}"
                value = fmt.format(_value)
            dump_data[k]['value'] = value

        addrs = sorted(dump_data)
        lines = []
        for addr in addrs:
            v = dump_data[addr]
            line = "0x{:08x} {} {} = {}".format(addr, v['type'], v['name'], v['value'])
            lines.append(line)
        return "\n".join(lines)

    def __json__(self):
        return self.get_dump()

    def get_analysis(self):
        return getattr(self, 'analysis')

    def is_win(self):
        return self.get_analysis().is_win

    @classmethod
    def from_bytes(cls, addr, nbytes, analysis=None, is_32bit=True):
        if analysis and analysis.has_internal_object(addr):
            return analysis.get_internal_object(addr)

        fmt = cls.bits32 if is_32bit else cls.bits64
        nfields = cls.named32 if is_32bit else cls.named64
        sz = struct.calcsize(fmt)
        data_unpack = struct.unpack(fmt, nbytes[:sz])
        kargs = {"addr": addr, 'analysis': analysis, 'updated': False}
        print(data_unpack, nfields, kargs)
        name_fields(data_unpack, nfields, fields=kargs)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        if analysis:
            analysis.add_internal_object(addr, d)
        return d

    @classmethod
    def unmangle_type(cls, string):
        return "UNKNOWN"

    def method_prototype(self, idx=0):
        raise BaseException("Not implemented")

    def field_prototype(self, idx=0):
        raise BaseException("Not implemented")

    @classmethod
    def make_ptr(cls, val):
        if val & 0x01:
            return val - 1
        return val

    def is_native_array_obj(self):
        return False

    @classmethod
    def is_python_native(cls, val):
        return isinstance(val, str) or \
            isinstance(val, int) or \
            isinstance(val, float) or \
            isinstance(val, int) or \
            isinstance(val, bytes)
