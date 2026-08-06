"""
Minimal MQTT 3.1.1 fixed-header / control-packet decoder.

The enforcement monitor (proxy.py) needs to inspect CONNECT, PUBLISH and
SUBSCRIBE packets in order to make ABAC + trust decisions, without
implementing (or depending on) a full client/broker stack. Every other
packet type is treated as opaque and simply relayed byte-for-byte.

This intentionally supports only what the research prototype needs
(QoS 0/1, no will-message parsing beyond skipping it correctly). It is
NOT a general-purpose MQTT library.
"""
from dataclasses import dataclass
from typing import Optional, Tuple

CONNECT, CONNACK, PUBLISH, PUBACK, SUBSCRIBE, SUBACK, \
    UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT = 1, 2, 3, 4, 8, 9, 10, 11, 12, 13, 14


def decode_remaining_length(buf: bytes, start: int) -> Tuple[int, int]:
    """Returns (remaining_length, bytes_consumed_for_length_field)."""
    multiplier = 1
    value = 0
    idx = start
    while True:
        b = buf[idx]
        value += (b & 0x7F) * multiplier
        idx += 1
        if (b & 0x80) == 0:
            break
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            raise ValueError("Malformed remaining length")
    return value, idx - start


def encode_remaining_length(length: int) -> bytes:
    out = bytearray()
    while True:
        b = length % 128
        length //= 128
        if length > 0:
            b |= 0x80
        out.append(b)
        if length <= 0:
            break
    return bytes(out)


@dataclass
class ParsedPacket:
    packet_type: int
    flags: int
    remaining_length: int
    header_len: int          # bytes used by fixed header (type/flags + length field)
    total_len: int           # header_len + remaining_length
    raw: bytes                # full raw packet bytes (may be truncated if not fully read yet)
    client_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    topic: Optional[str] = None
    qos: Optional[int] = None


def _read_utf8_string(buf: bytes, offset: int) -> Tuple[str, int]:
    strlen = int.from_bytes(buf[offset:offset + 2], "big")
    offset += 2
    s = buf[offset:offset + strlen].decode("utf-8", errors="replace")
    offset += strlen
    return s, offset


def try_parse(buf: bytes) -> Optional[ParsedPacket]:
    """
    Attempts to parse one full MQTT control packet from the start of `buf`.
    Returns None if `buf` does not yet contain a complete packet (caller
    should read more bytes and retry).
    """
    if len(buf) < 2:
        return None
    first_byte = buf[0]
    packet_type = (first_byte >> 4) & 0x0F
    flags = first_byte & 0x0F
    try:
        remaining_length, length_bytes = decode_remaining_length(buf, 1)
    except (IndexError, ValueError):
        return None

    header_len = 1 + length_bytes
    total_len = header_len + remaining_length
    if len(buf) < total_len:
        return None  # incomplete, need more bytes

    raw = buf[:total_len]
    pkt = ParsedPacket(packet_type, flags, remaining_length, header_len, total_len, raw)

    payload = raw[header_len:total_len]

    if packet_type == CONNECT:
        # variable header: protocol name, level, connect flags, keepalive
        proto_name, off = _read_utf8_string(payload, 0)
        off += 1  # protocol level
        connect_flags = payload[off]
        off += 1
        off += 2  # keep alive
        has_will = bool(connect_flags & 0x04)
        has_username = bool(connect_flags & 0x80)
        has_password = bool(connect_flags & 0x40)

        client_id, off = _read_utf8_string(payload, off)
        pkt.client_id = client_id

        if has_will:
            _, off = _read_utf8_string(payload, off)   # will topic
            will_msg_len = int.from_bytes(payload[off:off + 2], "big")
            off += 2 + will_msg_len

        if has_username:
            username, off = _read_utf8_string(payload, off)
            pkt.username = username
        if has_password:
            password, off = _read_utf8_string(payload, off)
            pkt.password = password

    elif packet_type == PUBLISH:
        qos = (flags >> 1) & 0x03
        pkt.qos = qos
        topic, off = _read_utf8_string(payload, 0)
        pkt.topic = topic

    elif packet_type == SUBSCRIBE:
        # payload: packet id (2 bytes) then repeated [topic filter][qos byte]
        off = 2
        topic, off = _read_utf8_string(payload, off)
        pkt.topic = topic  # first filter only (sufficient for this prototype)

    return pkt


def build_connack(return_code: int, session_present: bool = False) -> bytes:
    """return_code: 0=accepted, 5=not authorized (per MQTT 3.1.1 spec)."""
    payload = bytes([1 if session_present else 0, return_code])
    return bytes([CONNACK << 4]) + encode_remaining_length(len(payload)) + payload
