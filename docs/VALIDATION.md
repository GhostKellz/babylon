# Validation Report

**Date:** 2025-10-18

## Test Matrix

| Command | Purpose | Result |
| --- | --- | --- |
| `zig build test --summary all` | Runs module, integration, and CLI tests (including cache pruning + policy enforcement) | ✅ Pass |

## Notes

- Policy enforcement tests cover both success and failure paths for `babylon fetch` and `babylon policy audit`.
- Cache pruning is verified via unit tests to ensure unreferenced blobs are deleted while required artifacts remain.
- Tarball downloads now have explicit regression coverage for both `http://` and `https://` URLs (the latter via a test override), ensuring the CLI path stays wired while TLS fixtures incubate.
- Documentation highlights that tarballs are hashed and compared before caching; policies can enforce hash presence via `require_hash`.
