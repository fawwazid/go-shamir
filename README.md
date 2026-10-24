# go-shamir

Install: `go get github.com/fawwazid/go-shamir/v2@v2.0.0`.
See [v2 release notes](CHANGELOG.md) for breaking changes.

GF(257) Shamir secret sharing for Go 1.27.3, with no external dependencies.

## Usage

```go
package main

import (
 "fmt"
 "log"
 shamir "github.com/fawwazid/go-shamir/v2"
)

func main() {
 shares, err := shamir.Split([]byte("example secret"), 5, 3)
 if err != nil { log.Fatal(err) }
 encoded, err := shamir.EncodeSharesToHex(shares[:3])
 if err != nil { log.Fatal(err) }
 decoded, err := shamir.DecodeSharesFromHex(encoded)
 if err != nil { log.Fatal(err) }
 secret, err := shamir.Combine(decoded, 3)
 if err != nil { log.Fatal(err) }
 fmt.Println(string(secret))
}
```

## API and security

`Split(secret, total, threshold)` and `Combine(shares, threshold)` require a
threshold of at least two and at most 255 shares. Each share has a unique,
nonzero index. Each field element uses two bytes in little-endian order.
Hex helpers encode `index:hexvalue`.

Fewer than threshold correctly generated shares reveal no secret information.
The implementation does not authenticate shares, and `math/big` is not
constant-time. Protect shares independently and never mix sets.

This implementation is outside Go's validated cryptographic module.
`Split` and `Combine` return `ErrFIPSUnsupported` when FIPS mode is active.
There is no alternate cryptographic implementation or conversion path.

See [SECURITY.md](SECURITY.md). Run `go test ./...` and `go vet ./...`.
License: [MIT](LICENSE).
