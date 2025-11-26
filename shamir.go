package goshamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// fieldPrime is the largest prime less than 256, used for the finite field.
// This means secret bytes must be in the range [0, 250] for correct reconstruction.
// Bytes with values 251-255 cannot be represented in this finite field.
const fieldPrime = 251

// Share represents a single piece (share) of the secret.
//
// Index starts from 1 to match common Shamir references.
// Value holds the share data in the finite field used.
type Share struct {
	Index uint8
	Value []byte
}

// Split divides a secret into multiple shares using
// Shamir's Secret Sharing scheme.
//
// Parameters:
//   - secret: the secret data to be split.
//   - totalShares: total number of shares to generate (n).
//   - threshold: minimum number of shares required to reconstruct
//     the secret (k), where 2 <= threshold <= totalShares.
//
// Returns:
//   - slice of Share
//   - error if parameters are invalid or processing fails
func Split(secret []byte, totalShares, threshold int) ([]Share, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret must not be empty")
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if totalShares < threshold {
		return nil, errors.New("totalShares must be >= threshold")
	}
	if totalShares > 255 {
		return nil, errors.New("totalShares must be <= 255 (uint8 index limit)")
	}

	// Validate that all secret bytes are within the finite field range.
	// With fieldPrime = 251, bytes must be in [0, 250].
	for i, b := range secret {
		if int(b) >= fieldPrime {
			return nil, fmt.Errorf("secret byte at position %d has value %d, which exceeds the finite field limit of %d", i, b, fieldPrime-1)
		}
	}

	prime := defaultPrime()

	shares := make([]Share, totalShares)

	// Process the secret byte by byte (one polynomial per byte).
	for bytePos, b := range secret {
		coeffs := make([]*big.Int, threshold)
		coeffs[0] = big.NewInt(int64(b)) // constant term is the secret byte
		// Generate other random coefficients
		for i := 1; i < threshold; i++ {
			c, err := randIntMod(prime)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random coefficient: %w", err)
			}
			coeffs[i] = c
		}

		// Evaluate the polynomial for each x (share index)
		for i := 0; i < totalShares; i++ {
			x := big.NewInt(int64(i + 1)) // index starts at 1
			fx := evalPolynomial(coeffs, x, prime)
			if bytePos == 0 {
				shares[i] = Share{Index: uint8(i + 1), Value: []byte{}}
			}
			// fx is in [0, prime). For a per-byte field, cast back to byte.
			shares[i].Value = append(shares[i].Value, byte(fx.Int64()))
		}
	}

	return shares, nil
}

// Combine reconstructs the original secret from at least "threshold" shares.
//
// All shares must have the same Value length, otherwise an error is returned.
//
// If more than "threshold" shares are provided, only the first "threshold" shares
// from the input slice will be used for reconstruction. This is mathematically
// correct because any subset of "threshold" shares is sufficient to reconstruct
// the secret using Lagrange interpolation.
func Combine(shares []Share, threshold int) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}
	if len(shares) < threshold {
		return nil, errors.New("number of shares is less than threshold")
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}

	prime := defaultPrime()

	// Validate share indices: non-zero and unique
	indices := make(map[uint8]bool, threshold)
	for _, s := range shares[:threshold] {
		if s.Index == 0 {
			return nil, errors.New("share index must be non-zero")
		}
		if indices[s.Index] {
			return nil, errors.New("duplicate share index found")
		}
		indices[s.Index] = true
	}

	length := len(shares[0].Value)
	for _, s := range shares {
		if len(s.Value) != length {
			return nil, errors.New("share lengths are inconsistent")
		}
	}

	secret := make([]byte, length)

	// Reconstruct each byte using Lagrange interpolation at x = 0.
	for bytePos := 0; bytePos < length; bytePos++ {
		result := big.NewInt(0)
		for i := 0; i < threshold; i++ {
			xi := big.NewInt(int64(shares[i].Index))
			yi := big.NewInt(int64(shares[i].Value[bytePos]))

			num := big.NewInt(1)
			den := big.NewInt(1)
			for j := 0; j < threshold; j++ {
				if i == j {
					continue
				}
				xj := big.NewInt(int64(shares[j].Index))
				num.Mul(num, new(big.Int).Neg(xj))
				num.Mod(num, prime)

				tmp := new(big.Int).Sub(xi, xj)
				den.Mul(den, tmp)
				den.Mod(den, prime)
			}

			invDen, err := modInverse(den, prime)
			if err != nil {
				return nil, err
			}

			li := new(big.Int).Mul(num, invDen)
			li.Mod(li, prime)

			term := new(big.Int).Mul(yi, li)
			term.Mod(term, prime)
			result.Add(result, term)
			result.Mod(result, prime)
		}
		secret[bytePos] = byte(result.Uint64())
	}

	return secret, nil
}

// defaultPrime returns the prime used for the finite field.
//
// Currently 251 (the largest prime less than 256) is used so each
// share value fits safely in a byte.
func defaultPrime() *big.Int {
	return big.NewInt(fieldPrime)
}

// randIntMod returns a random integer in [0, prime).
func randIntMod(prime *big.Int) (*big.Int, error) {
	max := prime
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// evalPolynomial evaluates a polynomial with coefficients "coeffs"
// at point x, with all operations performed modulo prime.
func evalPolynomial(coeffs []*big.Int, x, prime *big.Int) *big.Int {
	result := big.NewInt(0)
	power := big.NewInt(1)
	for _, c := range coeffs {
		term := new(big.Int).Mul(c, power)
		term.Mod(term, prime)
		result.Add(result, term)
		result.Mod(result, prime)

		power.Mul(power, x)
		power.Mod(power, prime)
	}
	return result
}

// modInverse computes the modular inverse a^-1 modulo prime.
func modInverse(a, prime *big.Int) (*big.Int, error) {
	a = new(big.Int).Mod(a, prime)
	inv := new(big.Int).ModInverse(a, prime)
	if inv == nil {
		return nil, errors.New("modular inverse does not exist; this indicates corrupted or incompatible shares")
	}
	return inv, nil
}
