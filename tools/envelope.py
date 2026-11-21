"""
envelope.py -- the ACE-ADVT request codec, reconstructed from the disassembly.

Envelope (SystemBuffer, InputBufferLength must be exactly 0x24C):

    +0x000  DWORD  status / cmd_id        (driver writes status here)
    +0x004  ...    reserved / token
    +0x024  DWORD  payload_len            (must be <= 0x200)
    +0x028  BYTE   payload[0x200]
    +0x228  DWORD  key[8]                 (8 client-supplied round keys)
    +0x248  DWORD  key_select             (& 7 -> key index)
    +0x24C  --     end of the input buffer

Payload coding (sub_20580 @ 0x20580):

    p      = 0xDC6A2367
    state  = (payload_len * key) mod p
    for each 32-bit word:
        word  = src[i] ^ state
        state = ((word + src[i]) ^ 2) mod p
        state = (state ^ 2) mod p
    tail    = payload_len & 3 bytes -> zero filled
    returns 1 on success, 0 on failure

The opcode lives in the first dword of the *decoded* payload.  sub_6392E
validates it:

    eax = decoded[0] + 0x9C51BBD3
    if (eax > 0xB) reject
    if (bit eax of 0x907) reject           ; rejects 0,1,2,8,11
    if (g_flag_35008 != 0) return 0x30     ; global "armed" flag

so the usable opcode set is {3,4,5,6,7,9,10}.
"""
from __future__ import annotations

import struct

P = 0xDC6A2367
SCRAMBLE = 0x9C51BBD3
REJECT_MASK = 0x907          # bits 0,1,2,8,11 are refused
ENVELOPE_SIZE = 0x24C
PAYLOAD_MAX = 0x200
KEY_COUNT = 8


def decode(src: bytes, key: int) -> bytes:
    """decrypt payload words with the quadratic-congruential keystream"""
    n = len(src) // 4
    state = (len(src) * key) % P
    out = bytearray(len(src))
    for i in range(n):
        c = struct.unpack_from("<I", src, i * 4)[0]
        w = c ^ state
        struct.pack_into("<I", out, i * 4, w)
        state = ((w + c) * (w + c)) % P
        state = (state * state) % P
    return bytes(out)


def encode(plain: bytes, key: int) -> bytes:
    """inverse of decode: same state machine, plaintext/ciphertext swapped roles"""
    n = len(plain) // 4
    state = (len(plain) * key) % P
    out = bytearray(len(plain))
    for i in range(n):
        p = struct.unpack_from("<I", plain, i * 4)[0]
        c = p ^ state
        struct.pack_into("<I", out, i * 4, c)
        t = ((c ^ state) + c) % P         # (w + c) with w = plaintext
        state = (t * t) % P
        state = (state * state) % P
    return bytes(out)


TOKEN_BASE = (-SCRAMBLE) & 0xFFFFFFFF        # 0x63AE442D


def token(index: int) -> int:
    """client-visible command token for a logical opcode index 0..11"""
    return (TOKEN_BASE + index) & 0xFFFFFFFF


def index_of(tok: int) -> int:
    return (tok + SCRAMBLE) & 0xFFFFFFFF


def opcode_ok(tok: int) -> bool:
    v = index_of(tok)
    if v > 0xB:
        return False
    return not (REJECT_MASK >> v) & 1


def valid_opcodes() -> list[int]:
    """logical indices the dispatcher accepts"""
    return [k for k in range(12) if opcode_ok(token(k))]


def build(payload: bytes, key: int, key_select: int = 0, cmd: int = 0,
          out_len: int = 0x30) -> bytes:
    """assemble a 0x24C envelope the driver will accept"""
    if len(payload) > PAYLOAD_MAX:
        raise ValueError("payload too large")
    buf = bytearray(ENVELOPE_SIZE)
    struct.pack_into("<I", buf, 0x000, cmd)
    struct.pack_into("<I", buf, 0x024, len(payload))
    buf[0x028 : 0x028 + len(payload)] = payload
    for i in range(KEY_COUNT):
        struct.pack_into("<I", buf, 0x228 + i * 4, key if i == (key_select & 7) else 0)
    struct.pack_into("<I", buf, 0x248, key_select & 7)
    return bytes(buf)


def parse(buf: bytes) -> dict:
    if len(buf) < ENVELOPE_SIZE:
        raise ValueError("short envelope")
    return dict(
        cmd=struct.unpack_from("<I", buf, 0x000)[0],
        payload_len=struct.unpack_from("<I", buf, 0x024)[0],
        payload=buf[0x028 : 0x028 + PAYLOAD_MAX],
        keys=[struct.unpack_from("<I", buf, 0x228 + i * 4)[0] for i in range(KEY_COUNT)],
        key_select=struct.unpack_from("<I", buf, 0x248)[0] & 7,
    )


def make_request(opcode: int, body: bytes = b"", key: int = 0x11223344,
                 key_select: int = 0, out_len: int = 0x30) -> bytes:
    """full pipeline: opcode + body -> encoded envelope"""
    plain = bytearray(PAYLOAD_MAX)
    struct.pack_into("<I", plain, 0, token(opcode))
    plain[4 : 4 + len(body)] = body
    cipher = encode(bytes(plain), key)
    return build(cipher, key, key_select, cmd=0, out_len=out_len)


def selftest() -> bool:
    ok = True
    for key in (0x11223344, 0xDEADBEEF, 0):
        plain = bytes(range(64))
        c = encode(plain, key)
        d = decode(c, key)
        same = c != plain and d == plain
        ok &= same
        print(f"  key={key:#010x}  encode!=plain={c != plain}  roundtrip={d == plain}")
    print("  accepted indices:", valid_opcodes())
    print("  their tokens    :", [hex(token(k)) for k in valid_opcodes()])
    print("  rejected indices:", [k for k in range(12) if not opcode_ok(token(k))])
    return ok


if __name__ == "__main__":
    print("envelope codec self-test")
    raise SystemExit(0 if selftest() else 1)

