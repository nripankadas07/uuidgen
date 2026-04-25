"""uuidgen — UUID v4/v5 batch generator with base62 short form, strict parse, and named namespace tables.

Public API:

* :func:`generate_v4`     — list of cryptographically random UUIDs.
* :func:`generate_v5`     — namespaced SHA-1 UUID for a (namespace, name) pair.
* :func:`parse`           — accept canonical, 32-hex, braced, urn:, raw bytes, or base62.
* :func:`to_base62`       — encode UUID as fixed-width 22-char base62.
* :func:`from_base62`     — decode a base62 short form back to UUID.
* :func:`load_namespaces` — parse a TOML/JSON namespace table.
* :class:`Namespaces`     — convenience wrapper for namespace tables.
* :class:`UuidGenError`   — raised on invalid input (ValueError subclass).
* RFC-4122 namespace constants ``NAMESPACE_DNS``, ``NAMESPACE_URL``,
  ``NAMESPACE_OID``, ``NAMESPACE_X500``.
"""

from __future__ import annotations

from ._core import (
    NAMESPACE_DNS,
    NAMESPACE_OID,
    NAMESPACE_URL,
    NAMESPACE_X500,
    Namespaces,
    UuidGenError,
    from_base62,
    generate_v4,
    generate_v5,
    load_namespaces,
    parse,
    to_base62,
)

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

__version__ = "0.1.0"
