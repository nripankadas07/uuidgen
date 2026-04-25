"""Core uuidgen implementation — v4/v5 generation, parsing, base62 encoding."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterable, Mapping, Union
from uuid import UUID

__all__ = [
    "NAMESPACE_DNS",
    "NAMESPACE_OID",
    "NAMESPACE_URL",
    "NAMESPACE_X500",
    "Namespaces",
    "UuidGenError",
    "from_base62",
    "generate_v4",
    "generate_v5",
    "load_namespaces",
    "parse",
    "to_base62",
]


class UuidGenError(ValueError):
    """Raised for any malformed input to the uuidgen API.

    Subclasses :class:`ValueError` so callers who only catch ``ValueError``
    still see these errors, while callers who want to distinguish them can
    match on ``UuidGenError`` directly.
    """


# The four RFC 4122 well-known namespace UUIDs. Mirrored from the stdlib
# ``uuid`` module so callers don't have to import two things, and so we can
# add strict-typed helpers without monkey-patching stdlib.
NAMESPACE_DNS = UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
NAMESPACE_URL = UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
NAMESPACE_OID = UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")
NAMESPACE_X500 = UUID("6ba7b814-9dad-11d1-80b4-00c04fd430c8")


_BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_BASE62_INDEX = {char: index for index, char in enumerate(_BASE62_ALPHABET)}
# A 128-bit unsigned integer encodes to at most 22 base62 characters
# (ceil(128 / log2(62)) = 22). Shorter encodings are left-padded with "0".
_BASE62_WIDTH = 22
_MAX_UUID_INT = (1 << 128) - 1

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_CANONICAL = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_BRACED = re.compile(r"^\{(.+)\}$")
_URN = re.compile(r"^urn:uuid:(.+)$", re.IGNORECASE)
_BASE62_RE = re.compile(r"^[0-9A-Za-z]+$")


# ---------------------------------------------------------------------------
# v4 (random) generation
# ---------------------------------------------------------------------------

def generate_v4(count: int = 1) -> list[UUID]:
    """Generate ``count`` fresh random (v4) UUIDs.

    Args:
        count: number of UUIDs to generate. Must be a non-negative int.

    Returns:
        A list of ``count`` :class:`uuid.UUID` instances, each with
        version 4 and RFC 4122 variant bits correctly set.

    Raises:
        UuidGenError: if ``count`` is not an int or is negative.
    """
    if isinstance(count, bool) or not isinstance(count, int):
        raise UuidGenError(f"count must be an int, got {type(count).__name__}")
    if count < 0:
        raise UuidGenError(f"count must be non-negative, got {count}")
    return [_make_v4() for _ in range(count)]


def _make_v4() -> UUID:
    """Build a single v4 UUID from 16 fresh CSPRNG bytes."""
    raw = bytearray(os.urandom(16))
    # Set version (top 4 bits of byte 6) to 0b0100 == 4.
    raw[6] = (raw[6] & 0x0F) | 0x40
    # Set RFC 4122 variant (top 2 bits of byte 8) to 0b10.
    raw[8] = (raw[8] & 0x3F) | 0x80
    return UUID(bytes=bytes(raw))


# ---------------------------------------------------------------------------
# v5 (name-based SHA-1) generation
# ---------------------------------------------------------------------------

def generate_v5(
    namespace: Union[UUID, bytes, str],
    name: Union[str, bytes],
) -> UUID:
    """Generate a deterministic v5 UUID from a namespace and name.

    Args:
        namespace: a stdlib :class:`uuid.UUID`, exactly 16 raw bytes, or a
            string that :func:`parse` accepts.
        name: the object name within the namespace. Strings are encoded as
            UTF-8 before hashing; bytes are used verbatim.

    Returns:
        A :class:`uuid.UUID` with version 5 and RFC 4122 variant bits set.

    Raises:
        UuidGenError: if ``namespace`` or ``name`` is malformed or of the
            wrong type.
    """
    namespace_bytes = _coerce_namespace(namespace)
    name_bytes = _coerce_name(name)
    digest = hashlib.sha1(namespace_bytes + name_bytes, usedforsecurity=False)
    raw = bytearray(digest.digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x50  # version 5
    raw[8] = (raw[8] & 0x3F) | 0x80  # RFC 4122 variant
    return UUID(bytes=bytes(raw))


def _coerce_namespace(namespace: object) -> bytes:
    if isinstance(namespace, UUID):
        return namespace.bytes
    if isinstance(namespace, bytes):
        if len(namespace) != 16:
            raise UuidGenError(
                f"namespace bytes must be exactly 16 long, got {len(namespace)}"
            )
        return namespace
    if isinstance(namespace, str):
        return parse(namespace).bytes
    raise UuidGenError(
        f"namespace must be UUID, bytes, or str; got {type(namespace).__name__}"
    )


def _coerce_name(name: object) -> bytes:
    if isinstance(name, bytes):
        return name
    if isinstance(name, str):
        return name.encode("utf-8")
    raise UuidGenError(f"name must be str or bytes, got {type(name).__name__}")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse(value: Union[str, bytes, UUID]) -> UUID:
    """Parse ``value`` into a :class:`uuid.UUID`.

    Accepted forms:
      - an existing :class:`uuid.UUID` instance (returned verbatim)
      - exactly 16 raw bytes
      - canonical ``xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx``
      - 32 hex characters (no dashes)
      - ``{...}`` braced wrapper around either of the hex forms
      - ``urn:uuid:...`` URN form
      - 22-character base62 short form (see :func:`to_base62`)

    Leading/trailing whitespace on strings is stripped before matching.

    Raises:
        UuidGenError: if ``value`` does not match any accepted form.
    """
    if isinstance(value, UUID):
        return value
    if isinstance(value, bytes):
        if len(value) != 16:
            raise UuidGenError(
                f"bytes input must be exactly 16 bytes, got {len(value)}"
            )
        return UUID(bytes=value)
    if not isinstance(value, str):
        raise UuidGenError(f"parse expects str, bytes, or UUID; got {type(value).__name__}")

    stripped = value.strip()
    if not stripped:
        raise UuidGenError("parse received an empty string")
    return _parse_string(stripped)


def _parse_string(text: str) -> UUID:
    urn_match = _URN.match(text)
    if urn_match:
        return _parse_string(urn_match.group(1))
    braced_match = _BRACED.match(text)
    if braced_match:
        return _parse_string(braced_match.group(1))
    if _CANONICAL.match(text):
        return UUID(text)
    if _HEX32.match(text):
        return UUID(text)
    if len(text) == _BASE62_WIDTH and _BASE62_RE.match(text):
        return from_base62(text)
    raise UuidGenError(f"value is not a recognised UUID form: {text!r}")


# ---------------------------------------------------------------------------
# Base62 short form
# ---------------------------------------------------------------------------

def to_base62(value: Union[UUID, str, bytes]) -> str:
    """Encode a UUID as a fixed-width 22-character base62 string.

    The alphabet is ``0-9A-Za-z`` (RFC 4648-compatible for 0-9 then capital
    letters then lowercase letters). Output is always exactly 22 characters,
    left-padded with ``"0"`` if the numeric value is short.

    Args:
        value: anything :func:`parse` accepts.

    Returns:
        The 22-character base62 encoding.
    """
    uuid_obj = parse(value)
    return _int_to_base62(uuid_obj.int, _BASE62_WIDTH)


def from_base62(text: str) -> UUID:
    """Decode a base62 short form back to a :class:`uuid.UUID`.

    Accepts any base62 string whose decoded integer fits in 128 bits, but the
    canonical width is 22 characters. Strings longer than 22 characters or
    whose decoded integer exceeds 128 bits are rejected.

    Raises:
        UuidGenError: on non-string input, empty input, non-alphabet
            characters, or out-of-range values.
    """
    if not isinstance(text, str):
        raise UuidGenError(f"from_base62 expects str, got {type(text).__name__}")
    if not text:
        raise UuidGenError("from_base62 received an empty string")
    if len(text) > _BASE62_WIDTH:
        raise UuidGenError(
            f"base62 input exceeds {_BASE62_WIDTH} characters: {len(text)}"
        )
    value = 0
    for char in text:
        if char not in _BASE62_INDEX:
            raise UuidGenError(f"invalid base62 character: {char!r}")
        value = value * 62 + _BASE62_INDEX[char]
    if value > _MAX_UUID_INT:
        raise UuidGenError("base62 value exceeds 128-bit UUID range")
    return UUID(int=value)


def _int_to_base62(value: int, width: int) -> str:
    if value == 0:
        return "0" * width
    digits: list[str] = []
    while value > 0:
        value, remainder = divmod(value, 62)
        digits.append(_BASE62_ALPHABET[remainder])
    encoded = "".join(reversed(digits))
    return encoded.rjust(width, "0")


# ---------------------------------------------------------------------------
# Named-namespace tables
# ---------------------------------------------------------------------------

class Namespaces(Mapping[str, UUID]):
    """Immutable string-keyed namespace table, loaded from a dict or JSON file.

    Provides mapping access (``ns[\"dns\"]``, ``\"dns\" in ns``) plus a
    convenience :meth:`generate` that combines table lookup with v5
    generation.
    """

    __slots__ = ("_table",)

    def __init__(self, table: Mapping[str, UUID]) -> None:
        self._table: dict[str, UUID] = dict(table)

    def __getitem__(self, key: str) -> UUID:
        try:
            return self._table[key]
        except KeyError as err:
            raise UuidGenError(f"unknown namespace: {key!r}") from err

    def __iter__(self) -> Iterable[str]:
        return iter(self._table)

    def __len__(self) -> int:
        return len(self._table)

    def __contains__(self, key: object) -> bool:
        return key in self._table

    def __repr__(self) -> str:
        names = ", ".join(sorted(self._table))
        return f"Namespaces({names})"

    def generate(self, namespace_key: str, name: Union[str, bytes]) -> UUID:
        """Look up ``namespace_key`` in the table and v5-generate ``name``."""
