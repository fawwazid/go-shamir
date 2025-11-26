# go-shamir

A small Go package that implements Shamir's Secret Sharing for arbitrary byte slices.

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

// threshold must match the value used during Split (3 in this case)
recovered, err := goshamir.Combine(decoded[:3], 3)
if err != nil {
    panic(err)
}
```

## Testing

To run the tests for this module:

```bash
go test ./...
```

## License

See the `LICENSE` file.
