"""Wire protocol: framing and versioned, schema-checked messages.

Frame (24-byte header + payload), all integers big-endian:

    0   4  magic      b"TOY6"
    4  12  command    ASCII, NUL-padded (e.g. b"inv\\0\\0\\0...")
   16   4  length     u32, payload bytes; must be <= MAX_PAYLOAD (1 MiB)
   20   4  checksum   first 4 bytes of SHA256(SHA256(payload))
   24   n  payload    UTF-8 JSON object

A reader rejects a frame BEFORE reading its payload if the magic is wrong or
the length is too large, so a peer cannot make us allocate huge buffers.

Protocol version: 1, exchanged in the `version` handshake. Peers with another
version are refused.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re

MAGIC = b"TOY6"
HEADER_LEN = 24
MAX_PAYLOAD = 1 << 20
PROTOCOL_VERSION = 1
MAX_INV = 500
MAX_ADDR = 100
_HEX64 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9_.-]{1,32}")


class FrameError(Exception):
    """Unrecoverable: the byte stream can no longer be trusted (close the connection)."""

    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code


class MessageError(Exception):
    """Recoverable: one message was bad, the stream is still aligned."""

    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code


def checksum(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def encode(command: str, payload: dict) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode()
    if len(body) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    cmd = command.encode("ascii")
    if len(cmd) > 12:
        raise ValueError("command too long")
    return MAGIC + cmd.ljust(12, b"\0") + len(body).to_bytes(4, "big") + checksum(body) + body


async def read_frame(reader: asyncio.StreamReader) -> tuple[str, bytes]:
    """Read one frame. Raises FrameError (close) or returns (command, raw payload)."""
    hdr = await reader.readexactly(HEADER_LEN)
    if hdr[:4] != MAGIC:
        raise FrameError("BAD_MAGIC", f"bad magic {hdr[:4]!r}")
    length = int.from_bytes(hdr[16:20], "big")
    if length > MAX_PAYLOAD:
        raise FrameError("OVERSIZE", f"declared payload {length} bytes > max {MAX_PAYLOAD}")
    raw_cmd = hdr[4:16]
    payload = await reader.readexactly(length)
    try:
        cmd = raw_cmd.rstrip(b"\0").decode("ascii")
        if not cmd or "\0" in cmd or not cmd.isprintable():
            raise ValueError
    except ValueError:
        raise MessageError("BAD_COMMAND", f"unreadable command {raw_cmd!r}") from None
    if checksum(payload) != hdr[20:24]:
        raise MessageError("BAD_CHECKSUM", f"checksum mismatch on {cmd}")
    return cmd, payload


# --------------------------------------------------------------------------- schemas

def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise MessageError("BAD_SCHEMA", msg)


def _int(v, lo=0, hi=2**63) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _items(p: dict) -> None:
    _need(isinstance(p.get("items"), list) and 1 <= len(p["items"]) <= MAX_INV, f"items must be a list of 1..{MAX_INV}")
    for it in p["items"]:
        _need(isinstance(it, dict) and set(it) == {"type", "id"} and it["type"] in ("tx", "block")
              and isinstance(it["id"], str) and bool(_HEX64.fullmatch(it["id"])), f"bad inventory item {it!r}")


def _version(p):
    _need(set(p) == {"version", "node_id", "listen_port", "height", "tip", "agent"}, "version fields")
    _need(_int(p["version"]) and _int(p["listen_port"], 0, 65535) and _int(p["height"]), "version ints")
    _need(isinstance(p["node_id"], str) and bool(_ID.fullmatch(p["node_id"])), "node_id")
    _need(isinstance(p["tip"], str) and bool(_HEX64.fullmatch(p["tip"])), "tip")
    _need(isinstance(p["agent"], str) and len(p["agent"]) <= 64, "agent")


def _addr(p):
    _need(isinstance(p.get("peers"), list) and len(p["peers"]) <= MAX_ADDR, "peers list")
    for a in p["peers"]:
        _need(isinstance(a, dict) and set(a) == {"node_id", "host", "port"} and isinstance(a["host"], str)
              and _int(a["port"], 1, 65535) and isinstance(a["node_id"], str) and bool(_ID.fullmatch(a["node_id"])), "addr entry")


def _getblocks(p):
    _need(isinstance(p.get("locator"), list) and 1 <= len(p["locator"]) <= 64, "locator")
    _need(all(isinstance(h, str) and _HEX64.fullmatch(h) for h in p["locator"]), "locator hashes")


SCHEMAS = {
    "version": _version,
    "verack": lambda p: _need(p == {}, "verack is empty"),
    "getaddr": lambda p: _need(p == {}, "getaddr is empty"),
    "addr": _addr,
    "inv": _items,
    "getdata": _items,
    "notfound": _items,
    "tx": lambda p: _need(set(p) == {"tx"} and isinstance(p["tx"], dict), "tx payload"),
    "block": lambda p: _need(set(p) == {"block"} and isinstance(p["block"], dict), "block payload"),
    "getblocks": _getblocks,
    "ping": lambda p: _need(set(p) == {"nonce"} and _int(p["nonce"]), "ping nonce"),
    "pong": lambda p: _need(set(p) == {"nonce"} and _int(p["nonce"]), "pong nonce"),
    "reject": lambda p: _need(set(p) <= {"message", "code", "reason", "id"} and isinstance(p.get("code"), str), "reject"),
}


def parse(cmd: str, raw: bytes) -> dict:
    if cmd not in SCHEMAS:
        raise MessageError("UNKNOWN_COMMAND", f"unknown command {cmd!r}")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MessageError("BAD_JSON", f"{cmd}: payload is not valid UTF-8 JSON") from None
    _need(isinstance(payload, dict), f"{cmd}: payload must be an object")
    SCHEMAS[cmd](payload)
    return payload
