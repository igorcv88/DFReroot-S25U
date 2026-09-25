"""
Minimal, dependency-free ELF64 reader shared by the DFReroot audit tools.

Only what the Gate E/F/G audits need: header, section headers (by name),
symbol tables, dynamic symbols, relocations, program headers, build-id and the
.modinfo blob. Little-endian AArch64 is the only target we ship, but the parser
reads the encoding fields honestly and refuses anything it does not understand.
"""
import struct

EM = {0xB7: "AArch64 (EM_AARCH64)", 0x3E: "x86-64 (EM_X86_64)",
      0x28: "ARM (EM_ARM)", 0x00: "None"}
ELFCLASS = {1: "ELFCLASS32", 2: "ELFCLASS64"}
ELFDATA = {1: "little-endian (ELFDATA2LSB)", 2: "big-endian (ELFDATA2MSB)"}
ET = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNSYM = 11
SHN_UNDEF = 0
SHN_ABS = 0xFFF1


class Sym:
    __slots__ = ("name", "value", "size", "info", "other", "shndx", "bind", "typ")

    def __init__(self, name, value, size, info, other, shndx):
        self.name = name
        self.value = value
        self.size = size
        self.info = info
        self.other = other
        self.shndx = shndx
        self.bind = info >> 4
        self.typ = info & 0xF

    @property
    def is_undef(self):
        return self.shndx == SHN_UNDEF

    @property
    def bind_name(self):
        return {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}.get(self.bind, str(self.bind))


class Section:
    __slots__ = ("name", "type", "flags", "addr", "offset", "size",
                 "link", "info", "addralign", "entsize", "data", "_name_off")


class ELF64:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.raw = f.read()
        self.path = path
        b = self.raw
        if b[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.ei_class = b[4]
        self.ei_data = b[5]
        if self.ei_class != 2:
            raise ValueError("only ELF64 is supported (got %s)" % ELFCLASS.get(self.ei_class))
        self.en = "<" if self.ei_data == 1 else ">"
        (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
         self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
            self.en + "HHIQQQIHHHHHH", b, 16)
        self._sections = None

    @property
    def machine_name(self):
        return EM.get(self.e_machine, "0x%x" % self.e_machine)

    @property
    def type_name(self):
        return ET.get(self.e_type, "0x%x" % self.e_type)

    @property
    def class_name(self):
        return ELFCLASS.get(self.ei_class, str(self.ei_class))

    @property
    def data_name(self):
        return ELFDATA.get(self.ei_data, str(self.ei_data))

    def _read_str(self, base, off):
        end = self.raw.index(b"\x00", base + off)
        return self.raw[base + off:end].decode("utf-8", "replace")

    def sections(self):
        if self._sections is not None:
            return self._sections
        secs = []
        for i in range(self.e_shnum):
            o = self.e_shoff + i * self.e_shentsize
            (name, typ, flags, addr, offset, size, link, info, align, entsize) = \
                struct.unpack_from(self.en + "IIQQQQIIQQ", self.raw, o)
            s = Section()
            s.type, s.flags, s.addr, s.offset, s.size = typ, flags, addr, offset, size
            s.link, s.info, s.addralign, s.entsize = link, info, align, entsize
            s._name_off = name
            secs.append(s)
        # resolve names via shstrtab
        strbase = secs[self.e_shstrndx].offset
        for s in secs:
            s.name = self._read_str(strbase, s._name_off)
            s.data = self.raw[s.offset:s.offset + s.size] if s.type != 8 else b""  # SHT_NOBITS=8
        self._sections = secs
        return secs

    def section(self, name):
        for s in self.sections():
            if s.name == name:
                return s
        return None

    def _symbols_from(self, symsec):
        if symsec is None:
            return []
        strsec = self.sections()[symsec.link]
        strbase = strsec.offset
        out = []
        n = symsec.size // 24
        for i in range(n):
            o = symsec.offset + i * 24
            name_off, info, other, shndx, value, size = struct.unpack_from(
                self.en + "IBBHQQ", self.raw, o)
            name = self._read_str(strbase, name_off) if name_off else ""
            out.append(Sym(name, value, size, info, other, shndx))
        return out

    def symbols(self):
        return self._symbols_from(self.section(".symtab"))

    def dynsyms(self):
        return self._symbols_from(self.section(".dynsym"))

    def relocations(self):
        """Return {section_name: count} for every SHT_RELA section."""
        out = {}
        for s in self.sections():
            if s.type == SHT_RELA and s.entsize:
                out[s.name] = s.size // s.entsize
        return out

    def build_id(self):
        for name in (".note.gnu.build-id", ".note.android.ident"):
            s = self.section(name)
            if not s or not s.data:
                continue
            d = s.data
            off = 0
            while off + 12 <= len(d):
                namesz, descsz, ntype = struct.unpack_from(self.en + "III", d, off)
                off += 12
                nm = d[off:off + namesz]
                off += (namesz + 3) & ~3
                desc = d[off:off + descsz]
                off += (descsz + 3) & ~3
                if nm.startswith(b"GNU") and ntype == 3:
                    return desc.hex()
        return None

    def program_headers(self):
        out = []
        PT = {1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE",
              6: "PT_PHDR", 7: "PT_TLS", 0x6474e551: "PT_GNU_STACK",
              0x6474e552: "PT_GNU_RELRO", 0x6474e553: "PT_GNU_PROPERTY"}
        for i in range(self.e_phnum):
            o = self.e_phoff + i * self.e_phentsize
            (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = \
                struct.unpack_from(self.en + "IIQQQQQQ", self.raw, o)
            out.append(dict(type=PT.get(p_type, "0x%x" % p_type), flags=p_flags,
                            offset=p_offset, vaddr=p_vaddr, filesz=p_filesz,
                            memsz=p_memsz, align=p_align))
        return out

    def dt_needed(self):
        """DT_NEEDED library names from .dynamic."""
        dyn = self.section(".dynamic")
        dynstr = self.section(".dynstr")
        if not dyn or not dynstr:
            return []
        out = []
        n = dyn.size // 16
        for i in range(n):
            tag, val = struct.unpack_from(self.en + "qQ", self.raw, dyn.offset + i * 16)
            if tag == 1:  # DT_NEEDED
                out.append(self._read_str(dynstr.offset, val))
            if tag == 0:  # DT_NULL
                break
        return out
