import json


class MemRange(object):
    def __init__(self, **kargs):
        self.vaddr = 0
        self.paddr = 0
        self.vsize = 0
        self.size = 0
        self.data = None
        self.name = 'UNK'
        self.perms = '----'
        self.backend = None
        self.filename = None

        for k, v in kargs.items():
            setattr(self, k, v)

    def vaddr_in_range(self, vaddr):
        return self.vaddr <= vaddr and vaddr < self.vaddr + self.vsize

    def paddr_in_range(self, paddr):
        return self.paddr <= paddr and paddr < self.paddr + self.size

    def convert_paddr_to_vaddr(self, paddr):
        if not self.paddr_in_range(paddr):
            return None
        return self.vaddr + (paddr - self.paddr)

    def convert_vaddr_to_paddr(self, vaddr):
        if not self.vaddr_in_range(vaddr):
            return None
        return self.paddr + (vaddr - self.vaddr)

    def set_data(self, data):
        self.data = data

    def load_memory_load_memory_range_bytes_from_file(self, fh):
        fh.seek(self.paddr)
        self.set_data(fh.read(self.vsize))

    def read_bytes(self, offset, sz):
        if self.data is not None:
            return self.data[offset: offset + sz]
        return None

    @classmethod
    def from_json(cls, json_data: dict):
        if not isinstance(json_data, dict):
            return None

        keys = ['name', 'size', 'vsize', 'perm', 'paddr', 'vaddr']
        if not all([i in json_data for i in keys]):
            return None
        return cls(**json_data)

    def convert_vaddr_to_offset(self, vaddr):
        if self.vaddr_in_range(vaddr):
            return vaddr - self.vaddr
        return None

    def convert_paddr_to_offset(self, paddr):
        if self.paddr_in_range(paddr):
            return paddr - self.paddr
        return None

    def read_at_vaddr(self, vaddr, sz=1):
        offset = self.convert_vaddr_to_offset(vaddr)
        if offset is None or self.data is None:
            return None
        return self.read_bytes(offset, sz)

    def read_at_paddr(self, paddr, sz=1):
        offset = self.convert_vaddr_to_offset(paddr)
        if offset is None or self.data is None:
            return None
        return self.read_bytes(offset, sz)

    def load_segment_from_file(self, filename, offset=0):
        self.filename = filename
        fh = open(filename)
        fh.seek(offset)
        self.data = fh.read(self.size)
        # pad the virtual data
        if self.size < self.vsize:
            d = b'\x00' * (self.vsize - self.size)
            self.data = self.data + d

    def __str__(self):
        keys = ['name', 'size', 'vsize', 'perm', 'paddr', 'vaddr']
        s = []
        for k in keys:
            if isinstance(self.__dict__.get(k, None), int):
                s.append("{}: {:08x}".format(k, self.__dict__[k]))
            else:
                s.append("{}: {}".format(k, self.__dict__.get(k, None)))
        return "[MemReange: " + " ".join(s) + "]"

    def __repr__(self):
        return str(self)


class MemRanges(object):
    def __init__(self):
        self.vmem_ranges = {}
        self.pmem_ranges = {}
        self.mem_ranges = []
        self.paddr_sorted_ranges = []
        self.vmem_page_lookup = {}
        self.phy_page_lookup = {}
        self.page_mask = 0xfffffffffffff000
        self.page_size = 4096
        self.alignment = 4
        self.word_sz = 4

    def paddr_range(self):
        min_range = min([mr.paddr for mr in self.mem_ranges])
        max_range = max([mr.paddr + mr.size for mr in self.mem_ranges])
        return min_range, max_range

    def paddr_size(self):
        sz = sum([mr.size for mr in self.mem_ranges])
        return sz

    def vaddr_size(self):
        sz = sum([mr.vsize for mr in self.mem_ranges])
        return sz

    def vaddr_range(self):
        min_range = min([mr.vaddr for mr in self.mem_ranges])
        max_range = max([mr.vaddr + mr.vsize for mr in self.mem_ranges])
        return min_range, max_range

    def __str__(self):
        pstart, pend = self.paddr_range()
        vstart, vend = self.paddr_range()
        vsize = self.vaddr_size()
        size = self.paddr_size()
        fmt = "[MemRanges: paddr_range: {:08x}-{:08x} ({:08x}) vaddr_range: {:08x}-{:08x} ({:08x}) num_entries:{:08x}]"
        return fmt.format(pstart, pend, size, vstart, vsize, vsize, len(self.mem_ranges))

    def __repr__(self):
        self.sort_ranges()
        s = str(self)
        return s + "\n" + "\n\t".join([str(i) for i in self.mem_ranges])

    def sort_ranges(self):
        self.sort_ranges_by_vaddr()
        self.sort_ranges_by_paddr()

    def sort_ranges_by_vaddr(self):
        results = sorted(self.mem_ranges, key=lambda mr: mr.vaddr)
        self.mem_ranges = results
        return results

    def sort_ranges_by_paddr(self):
        results = sorted(self.mem_ranges, key=lambda mr: mr.paddr)
        self.paddr_sorted_ranges = results
        return results

    def __len__(self):
        return len(self.mem_ranges)

    def update_index(self):
        self.sort_ranges()
        self.phy_page_lookup = {}
        self.vmem_page_lookup = {}
        for mr in self.mem_ranges:
            self.vmem_ranges[mr.vaddr] = mr
            self.pmem_ranges[mr.paddr] = mr

            vaddr_base = mr.vaddr
            vaddr_end = mr.vaddr + mr.size
            paddr_base = mr.paddr
            paddr_end = mr.paddr + mr.size

            for page in range(vaddr_base, vaddr_end, self.page_size):
                self.vmem_page_lookup[page] = mr

            for page in range(paddr_base, paddr_end, self.page_size):
                self.phy_page_lookup[page] = mr

    def add_mem_range(self, mem_range: MemRange, update_index = False):
        self.mem_ranges.append(mem_range)
        if update_index:
            self.update_index()

    def valid_vaddr(self, vaddr: int) -> bool:
        addr = vaddr & self.page_size
        return addr in self.vmem_page_lookup


    def get_page(self, addr: int):
        return self.page_mask & addr

    def get_memrange_from_vaddr(self, vaddr: int) -> MemRange:
        page = self.get_page(vaddr)
        if page in self.vmem_page_lookup:
            return self.vmem_page_lookup[page]
        return None

    def get_memrange_from_paddr(self, paddr: int) -> MemRange:
        page = self.get_page(paddr)
        if page in self.phy_page_lookup:
            return self.phy_page_lookup[page]
        return None

    def convert_paddr_to_vaddr(self, paddr: int) -> int:
        mr = self.get_memrange_from_paddr(paddr)
        if mr:
            return mr.convert_paddr_to_vaddr(paddr)
        return None

    def convert_vaddr_to_paddr(self, vaddr: int):
        mr = self.get_memrange_from_vaddr(vaddr)
        if mr:
            return mr.convert_vaddr_to_paddr(vaddr)
        return None

    def load_memory_range_bytes_from_file(self, filename):
        fh = open(filename, 'rb')
        for _, mr in self.vmem_ranges.items():
            mr.filename = filename
            mr.load_memory_load_memory_range_bytes_from_file(fh)

    @classmethod
    def load_from_radare_section_json(cls, filename: str = None, json_data: list = None):
        if json_data is None and filename is None:
            return None

        if filename is not None and json_data is None:
            json_data = json.load(open(filename))

        if json_data is not None:
            mem_ranges = cls()
            for e in json_data:
                if isinstance(e, dict):
                    mr = MemRange.from_json(e)
                    mem_ranges.add_mem_range(mr)
            mem_ranges.update_index()
            return mem_ranges
        return None

    def read_at_vaddr(self, vaddr, sz):
        mr = self.get_memrange_from_vaddr(vaddr)
        if mr:
            return mr.read_at_vaddr(vaddr, sz)
        return None

    def read_at_paddr(self, paddr, sz):
        mr = self.get_memrange_from_paddr(paddr)
        if mr:
            return mr.read_at_paddr(paddr, sz)
        return None


class Analysis(object):
    def __init__(self, dmp_file=None, radare_file_data=None, load_memory_data=False):
        self.mem_ranges = MemRanges()
        self.radare_file = radare_file_data
        self.dmp_file = dmp_file
        self.radare_file_data = radare_file_data
        self.fh = None

        if radare_file_data is not None:
            self.load_from_radare_section_json(radare_file_data)

        if dmp_file is not None:
            self.open_memory_file(dmp_file)

        if load_memory_data:
            self.load_memory()

    def load_memory(self):
        if self.fh is None:
            raise Exception("Unable to load memory, no opened file")

        self.mem_ranges.load_memory_range_bytes_from_file(self.dmp_file)

    def open_memory_file(self, filename):
        self.memory_file = filename
        self.fh = open(filename, 'rb')

    def read_vaddr(self, vaddr, sz=1):
        mr = self.mem_ranges.get_memrange_from_vaddr(vaddr)
        if mr.data is None and self.fh is not None:
            mr.load_memory_load_memory_range_bytes_from_file(self.fh)
            if mr.data is None:
                return None
        return mr.read_at_vaddr(vaddr, sz)

    def read_paddr(self, paddr, sz=1):
        mr = self.mem_ranges.get_memrange_from_paddr(paddr)
        if mr.data is None and self.fh is not None:
            mr.load_memory_load_memory_range_bytes_from_file(self.fh)
            if mr.data is None:
                return None
        return mr.read_at_vaddr(paddr, sz)

    def load_from_radare_section_json(self, filename):
        self.radare_file_data = filename
        self.mem_ranges = MemRanges.load_from_radare_section_json(filename=filename)
        if self.mem_ranges is None:
            raise Exception("Failed to load memory ranges")
        return self.mem_ranges

    def get_paddr_from_vaddr(self, vaddr: int):
        mr = self.mem_ranges.get_memrange_from_vaddr(vaddr)
        return mr.convert_vaddr_to_paddr(vaddr)

    def get_paddr_base_from_vaddr(self, vaddr: int):
        mr = self.mem_ranges.get_memrange_from_vaddr(vaddr)
        return mr.paddr

    def get_vaddr_from_paddr(self, paddr: int):
        mr = self.mem_ranges.get_memrange_from_paddr(paddr)
        return mr.convert_paddr_to_vaddr(paddr)

    def get_vaddr_base_from_paddr(self, paddr: int):
        mr = self.mem_ranges.get_memrange_from_paddr(paddr)
        return mr.vaddr

    def valid_vaddr(self, vaddr: int):
        return self.mem_ranges.get_memrange_from_vaddr(vaddr) is not None

    def vaddr_section_size(self, vaddr: int):
        mr = self.mem_ranges.get_memrange_from_vaddr(vaddr)
        return mr.vsize

    def paddr_section_size(self, paddr: int):
        mr = self.mem_ranges.get_memrange_from_paddr(paddr)
        return mr.size

    def get_section(self, paddr: int = None, vaddr: int = None):
        if vaddr is None and paddr is None:
            return None
        if vaddr is not None:
            return self.mem_ranges.get_memrange_from_vaddr(vaddr)
        return self.mem_ranges.get_memrange_from_paddr(paddr)
