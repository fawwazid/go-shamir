# Changelog

## v2.0.0 — 2026-10-24

Define explicit secret-sharing boundaries and disable operations in FIPS mode.

### Breaking changes

- Module path is now `github.com/fawwazid/go-shamir/v2`. Update imports and use Go 1.27.3 or later.
- Split and Combine return ErrFIPSUnsupported whenever FIPS mode is enabled.
- Use the /v2 module path for this major release.

### Security and maintenance

- Retain uniform random coefficients over GF(257), share validation, and explicit two-byte field encoding.
- Simplify share decoding without changing empty-slice or validation behavior.
- The implementation does not authenticate shares and uses variable-time math/big arithmetic.
- Remove redundant code, obsolete comments, and compatibility paths.
- Add regression tests, current README examples, security guidance, and CI for Linux and Windows.
- FIPS policy tests use the frozen Go module v1.0.0 in both approved and strict assessment modes. This library is not independently FIPS certified; consult SECURITY.md for deployment requirements.

### Install

```sh
go get github.com/fawwazid/go-shamir/v2@v2.0.0
```
