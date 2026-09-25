"""
Minimal, dependency-free AVB (Android Verified Boot) vbmeta reader.

Sibling of tools/elf64.py, and for the same reason: the audits must run on any
host with nothing but python3. Depending on AOSP's avbtool would make the
provenance proof unreproducible exactly where it matters - in CI, and for a
reviewer who has no AOSP checkout.

Only what the vendor-provenance audit needs: the vbmeta header, the descriptor
list, hashtree and chain-partition descriptors, and the vbmeta digest.

The vbmeta digest is the value the bootloader publishes as
ro.boot.vbmeta.digest. It is NOT a hash of the partition image: it is
SHA-256 over the top-level vbmeta blob (header + authentication block +
auxiliary block, without the partition's trailing padding) followed by the same
blob of every chained vbmeta, walked in descriptor order. That is why
vbmeta.img alone cannot reproduce it - avbtool follows the chain descriptors,
and so must this.
"""
import hashlib
import os
import struct

HEADER_SIZE = 256
MAGIC = b"AVB0"

# Descriptor tags, as avbtool defines them. Off-by-one here is silent and
# catastrophic (a hash descriptor read as a hashtree yields garbage offsets that
# still parse), so they are named rather than inlined.
TAG_PROPERTY = 0
TAG_HASHTREE = 1
TAG_HASH = 2
TAG_KERNEL_CMDLINE = 3
TAG_CHAIN_PARTITION = 4

# AvbVBMetaImageHeader, packed, big-endian. 256 bytes exactly; the assert below
# is the guard against a mis-transcribed field.
_HEADER_FMT = ("!"
               "4s"    # magic
               "LL"    # required_libavb_version major, minor
               "Q"     # authentication_data_block_size
               "Q"     # auxiliary_data_block_size
               "L"     # algorithm_type
               "QQ"    # hash_offset, hash_size
               "QQ"    # signature_offset, signature_size
               "QQ"    # public_key_offset, public_key_size
               "QQ"    # public_key_metadata_offset, _size
               "QQ"    # descriptors_offset, descriptors_size
               "Q"     # rollback_index
               "L"     # flags
               "L"     # rollback_index_location
               "47s"   # release_string
               "x"     # release_string NUL
               "80x")  # reserved
_HEADER_KEYS = ("magic", "avb_version_major", "avb_version_minor",
                "auth_block_size", "aux_block_size", "algorithm_type",
                "hash_offset", "hash_size", "signature_offset",
                "signature_size", "public_key_offset", "public_key_size",
                "public_key_metadata_offset", "public_key_metadata_size",
                "descriptors_offset", "descriptors_size", "rollback_index",
                "flags", "rollback_index_location", "release_string")
assert struct.calcsize(_HEADER_FMT) == HEADER_SIZE, "AvbVBMetaImageHeader drift"

_HASHTREE_FMT = ("!"
                 "QQ"    # tag, num_bytes_following
                 "L"     # dm_verity_version
                 "Q"     # image_size
                 "Q"     # tree_offset
                 "Q"     # tree_size
                 "L"     # data_block_size
                 "L"     # hash_block_size
                 "L"     # fec_num_roots
                 "Q"     # fec_offset
                 "Q"     # fec_size
                 "32s"   # hash_algorithm
                 "L"     # partition_name_len
                 "L"     # salt_len
                 "L"     # root_digest_len
                 "L"     # flags
                 "60x")  # reserved
_CHAIN_FMT = ("!"
              "QQ"    # tag, num_bytes_following
              "L"     # rollback_index_location
              "L"     # partition_name_len
              "L"     # public_key_len
              "64x")  # reserved


class AvbError(Exception):
    """A vbmeta image that cannot be parsed. Never downgraded to a warning."""


class VBMeta:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.raw = f.read()
        if len(self.raw) < HEADER_SIZE:
            raise AvbError("%s: %d bytes, shorter than a vbmeta header"
                           % (path, len(self.raw)))
        vals = struct.unpack_from(_HEADER_FMT, self.raw, 0)
        self.header = dict(zip(_HEADER_KEYS, vals))
        if self.header["magic"] != MAGIC:
            raise AvbError("%s: magic is %r, not %r"
                           % (path, self.header["magic"], MAGIC))
        self.release_string = (self.header["release_string"]
                               .split(b"\x00")[0].decode("utf-8", "replace"))
        self.avb_version = "%d.%d" % (self.header["avb_version_major"],
                                      self.header["avb_version_minor"])

    @property
    def blob(self):
        """The bytes that enter the vbmeta digest: header + auth + aux.

        Deliberately not the whole file. A vbmeta partition is padded out to its
        partition size, and including the padding would produce a digest that
        matches nothing the bootloader ever publishes.
        """
        end = (HEADER_SIZE + self.header["auth_block_size"]
               + self.header["aux_block_size"])
        if end > len(self.raw):
            raise AvbError("%s: header claims %d bytes of blocks but the file "
                           "holds %d" % (self.path, end, len(self.raw)))
        return self.raw[:end]

    def descriptors(self):
        """[(tag, raw_descriptor_bytes)] in the order the image stores them."""
        aux = HEADER_SIZE + self.header["auth_block_size"]
        start = aux + self.header["descriptors_offset"]
        end = start + self.header["descriptors_size"]
        if end > len(self.raw):
            raise AvbError("%s: descriptor block runs past the end of the file"
                           % self.path)
        out, off = [], start
        while off < end:
            if off + 16 > end:
                raise AvbError("%s: truncated descriptor header" % self.path)
            tag, nbf = struct.unpack_from("!QQ", self.raw, off)
            if off + 16 + nbf > end:
                raise AvbError("%s: descriptor tag %d claims %d bytes, past the "
                               "end of the block" % (self.path, tag, nbf))
            out.append((tag, self.raw[off:off + 16 + nbf]))
            off += 16 + nbf
        return out

    def hashtrees(self):
        """{partition_name: parsed hashtree descriptor}."""
        out = {}
        for tag, d in self.descriptors():
            if tag != TAG_HASHTREE:
                continue
            ht = parse_hashtree(d)
            out[ht["partition_name"]] = ht
        return out

    def chain_partitions(self):
        """Chained partition names, in descriptor order (the digest's order)."""
        return [parse_chain(d) for tag, d in self.descriptors()
                if tag == TAG_CHAIN_PARTITION]


def parse_hashtree(d):
    fixed = struct.calcsize(_HASHTREE_FMT)
    (tag, nbf, version, image_size, tree_offset, tree_size, data_block_size,
     hash_block_size, fec_num_roots, fec_offset, fec_size, hash_algorithm,
     name_len, salt_len, root_len, flags) = struct.unpack_from(_HASHTREE_FMT, d, 0)
    if tag != TAG_HASHTREE:
        raise AvbError("not a hashtree descriptor (tag %d)" % tag)
    o = fixed
    need = o + name_len + salt_len + root_len
    if need > len(d):
        raise AvbError("hashtree descriptor is truncated (needs %d, has %d)"
                       % (need, len(d)))
    name = d[o:o + name_len].decode("utf-8", "replace"); o += name_len
    salt = d[o:o + salt_len].hex(); o += salt_len
    root = d[o:o + root_len].hex()
    return {
        "partition_name": name,
        "dm_verity_version": version,
        "image_size": image_size,
        "tree_offset": tree_offset,
        "tree_size": tree_size,
        "data_block_size": data_block_size,
        "hash_block_size": hash_block_size,
        "fec_num_roots": fec_num_roots,
        "fec_offset": fec_offset,
        "fec_size": fec_size,
        "hash_algorithm": hash_algorithm.split(b"\x00")[0].decode("utf-8", "replace"),
        "salt": salt,
        "root_digest": root,
        "flags": flags,
    }


def parse_chain(d):
    fixed = struct.calcsize(_CHAIN_FMT)
    tag, nbf, ril, name_len, pk_len = struct.unpack_from(_CHAIN_FMT, d, 0)
    if tag != TAG_CHAIN_PARTITION:
        raise AvbError("not a chain-partition descriptor (tag %d)" % tag)
    if fixed + name_len > len(d):
        raise AvbError("chain descriptor is truncated")
    return d[fixed:fixed + name_len].decode("utf-8", "replace")


def vbmeta_digest(top_path, child_for=None, _hasher=None, _depth=0, _chain=None):
    """Reproduce ro.boot.vbmeta.digest from a vbmeta image and its children.

    child_for(partition_name) -> path of that partition's vbmeta image. The
    default looks for "<name>-vbmeta.img" beside the top-level image. A chained
    partition whose vbmeta is absent raises: a digest computed over a subset of
    the chain would be a different number that happens to look like a result.

    Returns (hexdigest, [partition names walked, in order]).
    """
    if child_for is None:
        def child_for(name):
            return os.path.join(os.path.dirname(os.path.abspath(top_path)),
                                "%s-vbmeta.img" % name)
    hasher = _hasher or hashlib.sha256()
    chain = _chain if _chain is not None else []
    if _depth > 8:
        raise AvbError("vbmeta chain deeper than 8 levels; refusing to recurse")
    v = VBMeta(top_path)
    hasher.update(v.blob)
    for name in v.chain_partitions():
        path = child_for(name)
        if not os.path.exists(path):
            raise AvbError("chained partition %r has no vbmeta at %s; the digest "
                           "cannot be reproduced without it" % (name, path))
        chain.append(name)
        vbmeta_digest(path, child_for, hasher, _depth + 1, chain)
    return hasher.hexdigest(), chain
