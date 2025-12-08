# Go - Shamir's Secret Sharing

[![Go Reference](https://pkg.go.dev/badge/github.com/fawwazid/go-shamir.svg)](https://pkg.go.dev/github.com/fawwazid/go-shamir)
[![Go Report Card](https://goreportcard.com/badge/github.com/fawwazid/go-shamir)](https://goreportcard.com/report/github.com/fawwazid/go-shamir)

A cryptographically secure Go implementation of [Shamir's Secret Sharing](https://dl.acm.org/doi/10.1145/359168.359176) scheme for splitting sensitive data into multiple shares.

## Features

- **Information-theoretic security**: Fewer than threshold shares reveal zero information about the secret
- **Cryptographically secure**: Uses `crypto/rand` for random number generation
- **NIST-aligned**: Uses prime field GF(257) for full byte range support [0-255]
- **Zero dependencies**: Pure Go implementation with no external dependencies
- **Flexible encoding**: Hex encoding utilities for easy storage and transmission

## Installation

```bash
go get github.com/fawwazid/go-shamir
```

## Quick Start

Split a secret into `n` shares, requiring `k` (threshold) shares to reconstruct:

```go
package main

import (
    "fmt"
    "log"

    goshamir "github.com/fawwazid/go-shamir"
)

func main() {
    secret := []byte("my-encryption-key-32-bytes-long!")

    // Split into 5 shares, requiring 3 to reconstruct
    shares, err := goshamir.Split(secret, 5, 3)
    if err != nil {
        log.Fatal(err)
    }

    // Any 3 shares can reconstruct the secret
    recovered, err := goshamir.Combine(shares[:3], 3)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Recovered: %s\n", recovered)
}
```

## Share Encoding

Convert shares to hex strings for storage or transmission:

```go
// Encode shares to portable hex format
encoded, err := goshamir.EncodeSharesToHex(shares)
if err != nil {
    log.Fatal(err)
}
// Result: ["1:a1b2c3...", "2:d4e5f6...", ...]

// Decode back to shares
decoded, err := goshamir.DecodeSharesFromHex(encoded)
if err != nil {
    log.Fatal(err)
}

// Reconstruct with decoded shares
recovered, err := goshamir.Combine(decoded[:3], 3)
```

## API Reference

### Types

```go
// Share represents a single piece of the secret
type Share struct {
    Index uint8  // Unique identifier (1-255)
    Value []byte // Share data
}
```

### Functions

| Function | Description |
|----------|-------------|
| `Split(secret []byte, totalShares, threshold int) ([]Share, error)` | Splits a secret into shares |
| `Combine(shares []Share, threshold int) ([]byte, error)` | Reconstructs the secret from shares |
| `EncodeSharesToHex(shares []Share) ([]string, error)` | Encodes shares to hex strings |
| `DecodeSharesFromHex(encoded []string) ([]Share, error)` | Decodes hex strings to shares |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `FieldPrime` | 257 | Prime modulus for finite field |
| `MaxShares` | 255 | Maximum number of shares |
| `MinThreshold` | 2 | Minimum threshold value |

## Security Considerations

- **Threshold Selection**: Choose a threshold that balances security and availability
- **Share Distribution**: Distribute shares to independent parties or locations
- **Share Storage**: Protect individual shares as you would protect the secret
- **Random Generation**: Uses Go's `crypto/rand` for cryptographic randomness

## Testing

```bash
go test ./...
```

## License

See the [LICENSE](LICENSE) file.
