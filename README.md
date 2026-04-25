# uuidgen

Zero-dependency Python library for batch UUID generation with strong cryptographic randomness, RFC-4122 v5 namespacing, and base62 short forms.

## Install

```bash
pip install uuidgen
```

Requires Python 3.10+. No runtime dependencies.

## Quick example

```python
from uuidgen import (
    generate_v4, generate_v5, parse,
    to_base62, from_base62,
    NAMESPACE_DNS, NAMESPACE_URL,
)

# Batch v4 generation (cryptographically random)
ids = generate_v4(count=10)              # list[UUID]

# Namespaced v5 (deterministic SHA-1 hash)
u = generate_v5(NAMESPACE_DNS, "example.com")

# Base62 short form (22 chars, fixed width)
short = to_base62(u)                     # e.g. "5a3F9pxLbVm0aZ3..."
back = from_base62(short)                # round-trips exactly

# Tolerant parse
parse("550e8400-e29b-41d4-a716-446655440000")  # canonical
parse("{550e8400e29b41d4a716446655440000}")    # 32-hex / braced
parse("urn:uuid:550e8400-e29b-41d4-a716-446655440000")  # URN form
parse(b"\x55\x0e\x84..")                       # 16 raw bytes
parse(short)                                    # base62 short form
```

## Quality

- **85 tests, 100% line coverage**
- Zero runtime dependencies
- Strict type hints throughout
- Functions ≤30 lines, nesting ≤3 levels

## API

### `generate_v4(count: int = 1) -> list[UUID]`
Return `count` cryptographically random UUIDs (uses `os.urandom`).

### `generate_v5(namespace: UUID, name: str) -> UUID`
Return a deterministic SHA-1 namespaced UUID per RFC 4122.

### `parse(value) -> UUID`
Parse canonical (`8-4-4-4-12`), 32-hex, `{braced}`, `urn:uuid:`, 16 raw bytes, or base62.

### `to_base62(value: UUID) -> str` / `from_base62(text: str) -> UUID`
Fixed-width 22-char base62 round-trip (alphabet `0-9A-Za-z`).

### `load_namespaces(source: str | dict) -> Namespaces`
Load named namespaces from a TOML/JSON file or dict.

### `Namespaces(Mapping[str, UUID])` with `.generate(key, name)`
Look up by name and generate v5 UUIDs.

### `UuidGenError`
Subclass of `ValueError`.

## Running tests

```bash
pip install -e ".[dev]"
pytest                           # 85 tests
pytest --cov=uuidgen             # 100% line coverage
```

## License

MIT
