import re
import struct
from lz4 import frame
from lz4 import block
import argparse
import sys

import os


# https://github.com/craftspider/rbxm-rs
# https://docs.rs/rbx_binary/0.6.0/rbx_binary/
# https://github.com/Kat-Digital/RBXM-Reader/blob/master/RBXMReader.lua
# https://www.classy-studios.com/Downloads/RobloxFileSpec.pdf
# note the files only go up to page 24
# Nothing here: https://www.roblox.com/develop/library?CatalogContext=2&Subcategory=7&SortAggregation=5&PageNumber=25&LegendExpanded=true&Category=7&SearchId=013f9db9-a524-472c-8cd1-a7a3e09ee0c7

# from parse_rbxm import *
# data = open('assets/1032987767_Model-Stretch-Widen-V2.rbxm', 'rb').read()
# props = [b'PROP' + i for i in data.split(b'PROP')[1:]]
# interest= [ i for i in props if i.find(b'local') > -1]
# x = ObjectHeader.deserialize(interest[0], uncompress=True)
# oh = ObjectHeader(**x)


class StringProp:
    TAG = b'\x01'
    str_tag = 'c'
    str_size = '<I'
    str_data = None

    off_tag = 0
    off_size = off_tag + struct.calcsize(str_tag)
    off_data = off_size + struct.calcsize(str_size)

    VALUES = ['tag', 'type', 'size', 'data']

    def __init__(self, **kargs):
        for k, v in kargs.items():
            setattr(self, k, v)

    @classmethod
    def deserialize(cls, data_stream):
        tag = struct.unpack_from(cls.str_tag, data_stream)[0]
        size = struct.unpack_from(cls.str_size, data_stream, cls.off_size)[0]
        data = data_stream[cls.off_data: cls.off_data + size]
        return {'tag': tag, 'type': 'String', 'size': size, 'data': data}

    @classmethod
    def serialize(cls, prop):
        data = prop.get('data', b'')
        size = struct.pack(cls.str_size, len(data))
        data = data.encode('utf8') if not isinstance(data, bytes) else data
        return cls.TAG + size + data

    def to_dict(self):
        d = {k: getattr(self, k, None) for k in self.VALUES}
        return d

    def to_stream(self):
        return self.serialize(self.to_dict())


class Property:
    PROPS = {
        b'\x01': StringProp,
    }

    @classmethod
    def deserialize(cls, data_stream):
        tag = struct.unpack_from('c', data_stream)[0]
        if tag not in cls.PROPS:
            return {}

        PP = cls.PROPS[tag]
        return PP.deserialize(data_stream)

    @classmethod
    def serialize(cls, prop):
        tag = prop.get('tag', None)
        if tag not in cls.PROPS:
            return None

        PP = cls.PROPS[tag]
        return PP.serialize(prop)

    @classmethod
    def is_property(cls, prop):
        return not isinstance(prop, None) and \
            isinstance(prop, StringProp) or \
            False

    @classmethod
    def create_property(cls, **kargs):
        tag = kargs.get('tag', None)
        if tag not in cls.PROPS:
            return None
        PP = cls.PROPS[tag]
        return PP(**kargs)


class Source:
    str_index = '<I'
    str_name_len = '<I'
    str_name = None
    str_prop = None

    off_index = 0
    off_name_len = off_index + struct.calcsize(str_index)
    off_name = off_name_len + struct.calcsize(str_name_len)
    off_prop = None

    VALUES = ['index', 'prop', 'name', 'name_len', 'data']

    def __init__(self, **kargs):
        for k, v in kargs.items():
            setattr(self, k, v)

        # Lazy handle creation of prop instance
        if isinstance(self.prop, dict):
            self.prop = Property.create_property(**self.prop)

    def to_dict(self):
        d = {k: getattr(self, k, None) for k in self.VALUES}
        d['prop'] = self.prop.to_dict() if Property.is_property(self.prop) else \
            self.prop if isinstance(self.prop, dict) else None
        return d

    @classmethod
    def from_stream(cls, data_stream):
        x = cls.deserialize(data_stream)
        return cls(**x)

    def to_stream(self):
        return self.serialize(self.index, self.name, self.prop)

    @classmethod
    def deserialize(cls, data_stream, uncompress=False):
        index = struct.unpack_from(cls.str_index, data_stream, cls.off_index)[0]
        name_len = struct.unpack_from(cls.str_name_len, data_stream, cls.off_name_len)[0]
        name = data_stream[cls.off_name: cls.off_name + name_len]
        prop_offset = name_len + cls.off_name
        prop = Property.deserialize(data_stream[prop_offset:])

        return {'index': index, 'prop': prop, 'name': name, 'name_len': name_len, "data": data_stream[prop_offset:]}

    @classmethod
    def serialize(cls, index, name, prop):
        index = struct.pack(cls.str_index, index)
        name_len = struct.pack(cls.str_name_len, len(name))
        name_ = name.encode('utf8') if not isinstance(name, bytes) else name
        prop = Property.serialize(prop)

        return index + name_len + name + prop


class ObjectHeader(object):
    str_header = '4s'
    str_compressed_length = '<I'
    str_uncompressed_length = '<I'
    str_nop = '<I'
    str_data = None

    off_header = 0
    off_compressed_length = off_header + struct.calcsize(str_header)
    off_uncompressed_length = off_compressed_length + struct.calcsize(str_compressed_length)
    off_nop = off_uncompressed_length + struct.calcsize(str_uncompressed_length)
    off_data = off_nop + struct.calcsize(str_nop)

    VALUES = ["header", "compressed_length", "uncompressed_length", "cdata", "data"]

    def __init__(self, **kargs):
        for k, v in kargs.items():
            setattr(self, k, v)

        if self.data is None:
            self.data = b''

    @classmethod
    def from_stream(cls, data_stream, uncompress=True):
        x = cls.deserialize(data_stream, uncompress=uncompress)
        return cls(**x)

    def to_stream(self):
        return self.serialize(self.header, self.data)

    @classmethod
    def deserialize(cls, data_stream, uncompress=False):
        header = struct.unpack_from(cls.str_header, data_stream, cls.off_header)[0]
        compressed_length = struct.unpack_from(cls.str_compressed_length, data_stream, cls.off_compressed_length)[0]
        uncompressed_length = struct.unpack_from(cls.str_uncompressed_length, data_stream, cls.off_uncompressed_length)[
            0]
        cdata = data_stream[cls.off_data: cls.off_data + compressed_length]
        data = None
        if uncompress:
            data = cls.decompress(cdata, uncompressed_length)

        return {'header': header, 'compressed_length': compressed_length, 'uncompressed_length': uncompressed_length,
                'cdata': cdata, 'data': data}

    @classmethod
    def decompress(cls, data_stream, uncompressed_length):
        return block.decompress(data_stream, uncompressed_size=uncompressed_length)

    @classmethod
    def compress(cls, data_stream):
        return block.compress(data_stream)

    @classmethod
    def serialize(cls, header, bdata):
        data_stream = b''
        header = struct.pack(cls.str_header, header)
        # length = struct.pack(cls.str_uncompressed_length, len(bdata))
        nop = '\x00' * 4
        data = cls.compress(bdata)
        clength = struct.pack(cls.str_compressed_length, len(data))
        return header + clength + data


def lazy_extract_properties(data_stream):
    prop_pos = [m.start() for m in re.finditer(b'PROP', data_stream)]
    props = [data_stream[pos:] for pos in prop_pos]
    objs = []
    for ds in props:
        try:
            oh = ObjectHeader.from_stream(ds)
            objs.append(oh)
        except:
            pass
    return objs


def lazy_extract_source(data_stream):
    ohs = lazy_extract_properties(data_stream)
    source_props = [i for i in ohs if
                    i.data is not None and i.data.find(b'LinkedSource') == -1 and i.data.find(b'Source\x01') > -1]
    srcs = [Source.from_stream(i.data) for i in source_props]
    return srcs


def read_asset_sources(asset_filename):
    data_stream = open(asset_filename, 'rb').read()
    return lazy_extract_source(data_stream)


def read_assets_dir(asset_dir):
    files = [i for i in os.listdir(asset_dir)]

    results = {}
    for i in files:
        filename = os.path.join(asset_dir, i)
        try:
            srcs = read_asset_sources(filename)
            data = [src.prop.data for src in srcs]
            results[i] = data

        except:
            print("Failed to parse {}".format(filename))
    return results


parser = argparse.ArgumentParser('extract RBXM Lua strings')
parser.add_argument('--asset', type=str, default=None, help='asset file to read')
parser.add_argument('--out', type=str, default=None, help='place to dump finds')

if __name__ == "__main__":
    args = parser.parse_args()

    if args.asset is None:
        parser.print_help()
        sys.exit(0)

    srcs = read_asset_sources(args.asset)

    out = None if args.out is None else open(args.out, 'w')
    data = []

    for src in srcs:
        data.append(src.prop.data)

    if out is None:
        for d in data:
            print(d)
    else:
        out.write(b' '.join(data).decode('utf8'))