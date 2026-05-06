# CMVP checker

Rust CLI for searching CMVP modules by algorithm.

It uses two paths:

1. **Live CMVP search** for algorithms the validated-modules page can find directly.
2. **Section 2.5 policy scanning** for terms like `ML-KEM` or `LMS`, using cached certificate HTML and security policy PDFs/text.

## Build

```bash
cargo build --release
```

Binary:

```bash
./target/release/cmvp-checker
```

## Basic usage

Search active modules:

```bash
./target/release/cmvp-checker ML-KEM
./target/release/cmvp-checker LMS
./target/release/cmvp-checker ML-KEM LMS --status Active
```

Write structured output:

```bash
./target/release/cmvp-checker ML-KEM --json mlkem.json
./target/release/cmvp-checker LMS --csv lms.csv
```

## Cache

The tool stores cached data in `./cmvp_search_cache` by default:

- `certificates/` - cached CMVP certificate HTML pages
- `security-policies/` - cached policy PDFs and extracted `.txt` files

Refresh cached certificate pages and security policies:

```bash
./target/release/cmvp-checker ML-KEM --fresh
```

Use an existing cache directory:

```bash
./target/release/cmvp-checker ML-KEM --cache-dir /tmp/cmvp_search_cache
```

## Offline mode

If you already have cached certificate HTML and policy text, you can avoid live NIST requests:

```bash
./target/release/cmvp-checker --offline --cache-dir /tmp/cmvp_search_cache ML-KEM LMS
```

Offline mode skips live CMVP/CAVP lookups and scans only the cached files.

## Output

For policy-derived matches, the tool reports:

- **Module Cert**
- **Vendor**
- **Module Name**
- **CAVP Cert**
- **CAVP Algorithm**
- **Operation**

Example:

```text
5247 | Geomys LLC | Go Cryptographic Module | A6650 | ML-KEM EncapDecap | EncapDecap
5247 | Geomys LLC | Go Cryptographic Module | A6650 | ML-KEM KeyGen     | KeyGen
```
