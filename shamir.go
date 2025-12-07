// Package goshamir implements Shamir's Secret Sharing scheme over the finite field GF(2^8).
// Provides capabilities to split a secret into multiple shares and reconstruct it
// from a subset of those shares.
package goshamir

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Share represents a single piece (share) of the secret.
// Index is the x-coordinate (1-255) and Value is the y-coordinate data.
type Share struct {
	Index uint8
	Value []byte
}

// Split divides a secret into n shares (totalShares), requiring k shares (threshold)
// to reconstruct the secret.
//
// It returns a slice of Share and an error if the inputs are invalid.
//
// Properties:
//   - Field: GF(2^8) with Rijndael irreducible polynomial 0x11B.
//   - Max shares: 255.
//   - Secret size: Any length.
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

	shares := make([]Share, totalShares)
	// Initialize indices
	for i := 0; i < totalShares; i++ {
		shares[i] = Share{Index: uint8(i + 1), Value: make([]byte, len(secret))}
	}

	// Process the secret byte by byte
	for i, b := range secret {
		// Generate random polynomial coefficients for this byte.
		// coeffs[0] = b (secret)
		// we need (threshold-1) random coefficients.
		coeffs := make([]uint8, threshold)
		coeffs[0] = b

		// Random coefficients
		randBytes := make([]byte, threshold-1)
		if _, err := rand.Read(randBytes); err != nil {
			return nil, fmt.Errorf("rng error: %v", err)
		}
		for j := 0; j < threshold-1; j++ {
			coeffs[j+1] = randBytes[j]
		}

		// Evaluate polynomial for each share
		for shareIdx := 0; shareIdx < totalShares; shareIdx++ {
			x := uint8(shareIdx + 1)
			y := evalPoly(coeffs, x)
			shares[shareIdx].Value[i] = y
		}
	}

	return shares, nil
}

// Combine reconstructs the original secret from at least threshold shares.
// It uses Lagrange interpolation over GF(2^8).
//
// The length of the provided shares slice must be at least threshold.
// If it is larger, only the first threshold shares are used.
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

	// x coordinates for the first 'threshold' shares
	xs := make([]uint8, threshold)
	for i := 0; i < threshold; i++ {
		xs[i] = shares[i].Index
	}

	// Lagrange Interpolation at x=0
	// L(0) = sum( y_i * basis_i(0) )
	// basis_i(0) = product( (0 - x_j) / (x_i - x_j) ) for j != i
	// In GF(2^8), subtraction is XOR (same as addition).
	// So (0 - x_j) = (0 ^ x_j) = x_j
	// basis_i(0) = product( x_j / (x_i ^ x_j) )
	//
	// Note: The denominator (xs[j] ^ xs[m]) is guaranteed to be non-zero
	// because duplicate indices are checked above (lines 93-102), ensuring
	// that xs[j] != xs[m] for all j != m.

	for i := 0; i < length; i++ {
		// Reconstruct i-th byte of secret
		// ys are the values of shares at byte i
		ys := make([]uint8, threshold)
		for j := 0; j < threshold; j++ {
			ys[j] = shares[j].Value[i]
		}

		result := uint8(0)
		for j := 0; j < threshold; j++ {
			num := uint8(1) // numerator
			den := uint8(1) // denominator

			for m := 0; m < threshold; m++ {
				if m == j {
					continue
				}
				// num *= x_m
				num = mul(num, xs[m])
				// den *= (x_j - x_m) -> x_j ^ x_m
				den = mul(den, xs[j]^xs[m])
			}

			// basis = num / den
			basis, err := div(num, den)
			if err != nil {
				return nil, err
			}

			// term = y_j * basis
			term := mul(ys[j], basis)

			result ^= term // Add to result
		}
		secret[i] = result
	}

	return secret, nil
}

// evalPoly evaluates polynomial with coeffs at x in GF(2^8).
func evalPoly(coeffs []uint8, x uint8) uint8 {
	// Horner's method
	// c_0 + x(c_1 + x(c_2 + ...))
	// But our coeffs are normally index increasing: a0 + a1*x + ...
	// So we process from high degree down to 0.
	degree := len(coeffs) - 1
	result := coeffs[degree]
	for i := degree - 1; i >= 0; i-- {
		result = mul(result, x)
		result = result ^ coeffs[i] // add
	}
	return result
}

// --- GF(2^8) Arithmetic using Log/Exp tables ---
// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
// Generator: 3

var (
	gfExp [512]uint8
	gfLog [256]uint8
)

func init() {
	// Generate Log and Exp tables for GF(2^8)
	// Base is 3.
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = uint8(x)
		gfLog[x] = uint8(i)

		// Multiply x by 3 in GF(2^8) using the reduction polynomial 0x11B.
		// This is used to generate the exponentiation and logarithm tables for the field.
		y := x << 1
		if x&0x80 != 0 {
			y ^= 0x11B
		}
		y ^= x // add x (multiply by 1)

		x = y & 0xFF
	}
	// Optimization for avoiding modulo 255 checks in mul
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
	// gfLog[0] is unused because mul() and div() handle zero inputs explicitly.
}

// mul multiplies two numbers in GF(2^8).
func mul(a, b uint8) uint8 {
	if a == 0 || b == 0 {
		return 0
	}
	// return gfExp[(int(gfLog[a]) + int(gfLog[b])) % 255]
	// Using extended Exp table to avoid modulo:
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// div divides a by b in GF(2^8), returning an error if b is zero.
func div(a, b uint8) (uint8, error) {
	if a == 0 {
		return 0, nil
	}
	if b == 0 {
		return 0, errors.New("division by zero in GF(2^8)")
	}
	// a / b = a * b^-1
	// log(a/b) = log(a) - log(b) (mod 255)
	// If log(a) < log(b), add 255.
	diff := int(gfLog[a]) - int(gfLog[b])
	if diff < 0 {
		diff += 255
	}
	return gfExp[diff], nil
}
