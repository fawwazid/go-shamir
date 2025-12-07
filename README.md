# Go - Shamir's Secret Sharing

[![Go Report Card](https://goreportcard.com/badge/github.com/fawwazid/go-shamir)](https://goreportcard.com/report/github.com/fawwazid/go-shamir)
[![Go Reference](https://pkg.go.dev/badge/github.com/fawwazid/go-shamir.svg)](https://pkg.go.dev/github.com/fawwazid/go-shamir)

A small Go package that implements Shamir's Secret Sharing for arbitrary byte slices over the finite field GF(2^8) (Rijndael's finite field).

This implementation supports splitting sequences of bytes (like passwords, keys, or data) into shares and reconstructing them.

## Installation

```bash
go get github.com/fawwazid/go-shamir
```

## Basic Usage

Split a secret into `n` shares, with a threshold `k` required to reconstruct it:

```go
package main

import (
    "fmt"

    goshamir "github.com/fawwazid/go-shamir"
)

func main() {
    secret := []byte("very important secret")

    // Split the secret into 5 shares, with a threshold of 3
    // Works with any byte values (0-255).
    shares, err := goshamir.Split(secret, 5, 3)
    if err != nil {
        panic(err)
    }

    // Use any 3 shares to reconstruct the secret
    recovered, err := goshamir.Combine(shares[:3], 3)
    if err != nil {
        panic(err)
    }

    fmt.Println(string(recovered))
}
```

## Encoding Shares

You can convert shares to hex strings for easy storage or transmission
(for example, in JSON, environment variables, or config files):

```go
encoded := goshamir.EncodeSharesToHex(shares)
// store or send `encoded`

decoded, err := goshamir.DecodeSharesFromHex(encoded)
if err != nil {
    panic(err)
}

recovered, err := goshamir.Combine(decoded[:3], 3)
if err != nil {
    panic(err)
}
```

## Security & Implementation Details

- **Field Arithmetic**: Uses GF(2^8) with the AES irreducible polynomial $x^8 + x^4 + x^3 + x + 1$ (0x11B). This allows perfect reconstruction of all 256 byte values.
- **Randomness**: Uses `crypto/rand` for cryptographic secure random coefficient generation.
- **Max Shares**: Supports up to 255 shares (indices 1-255).
- **Constant Time**: Field multiplication uses log/exp table lookups. While efficient, table lookups may be susceptible to cache-timing side channels in extremely specific environments.

## Testing

To run the tests:

```bash
go test -v .
```

## License

See the `LICENSE` file.
