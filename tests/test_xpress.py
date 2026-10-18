"""Xpress (LZ77 + DIRECT2) as WSUS compresses its SOAP replies."""

import random
import struct

from pcapforge import xpress


def test_blocks_match_the_ms_xca_plain_lz77_examples():
    # [MS-XCA] section 3.1: 26 literals, then the end bits; "abc" x 100 as one long match.
    assert xpress._compress_block(b"abcdefghijklmnopqrstuvwxyz") == bytes.fromhex("3f000000") + b"abcdefghijklmnopqrstuvwxyz"
    assert xpress._compress_block(b"abc" * 100) == bytes.fromhex("ffffff1f6162631700 0fff2601".replace(" ", ""))


def test_long_and_mixed_input_round_trips_in_65535_byte_blocks():
    rng = random.Random(7)
    soap = b"<soap:Envelope><ConfigurationProperty><Name>x</Name></ConfigurationProperty>" * 2000
    data = soap + bytes(rng.randrange(4) for _ in range(70_000)) + b"z" * 300
    packed = xpress.compress(data)
    assert xpress.decompress(packed) == data
    original, compressed = struct.unpack_from("<ii", packed)
    assert original == xpress.BLOCK and compressed < original
