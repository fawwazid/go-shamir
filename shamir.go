// Package goshamir implements Shamir's Secret Sharing scheme.
package goshamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

const (
	// FieldPrime is the prime modulus for finite field GF(257).
	FieldPrime = 257
	// MaxShares is the maximum number of shares (uint8 limit).
	// Share indices are uint8 in the range 1-255 (inclusive); index 0 is reserved/invalid.
	MaxShares = 255
	// MinThreshold is the minimum threshold for security.
	MinThreshold = 2
)

// Share represents a single piece of the secret.
type Share struct {
	Index uint8
	Value []byte
}

// Split divides a secret into n shares requiring k shares to reconstruct.
func Split(secret []byte, totalShares, threshold int) ([]Share, error) {
	if err := validateSplitParams(secret, totalShares, threshold); err != nil {
		return nil, err
	}

	prime := big.NewInt(FieldPrime)

	shares := make([]Share, totalShares)
	for i := range shares {
		shares[i] = Share{
			Index: uint8(i + 1),
			Value: make([]byte, 0, len(secret)*2),
		}
	}

	for _, secretByte := range secret {
		coeffs, err := generatePolynomialCoeffs(secretByte, threshold, prime)
		if err != nil {
			return nil, err
		}

		for i := range shares {
			x := big.NewInt(int64(shares[i].Index))
			y := evaluatePolynomial(coeffs, x, prime)
			val := y.Uint64()
			shares[i].Value = appendFieldElement(shares[i].Value, val)
		}
	}

	return shares, nil
}

// Combine reconstructs the secret from shares using Lagrange interpolation.
func Combine(shares []Share, threshold int) ([]byte, error) {
	if err := validateCombineParams(shares, threshold); err != nil {
		return nil, err
	}

	prime := big.NewInt(FieldPrime)
	usedShares := shares[:threshold]

	if err := validateShareIndices(usedShares); err != nil {
		return nil, err
	}

	valueLen := len(shares[0].Value)
	secretLen := valueLen / 2
	secret := make([]byte, secretLen)

	for bytePos := 0; bytePos < secretLen; bytePos++ {
		result, err := lagrangeInterpolate(usedShares, bytePos, prime)
		if err != nil {
			return nil, err
		}
		secret[bytePos] = byte(result.Uint64() % 256)
	}

	return secret, nil
}

func generatePolynomialCoeffs(secretByte byte, threshold int, prime *big.Int) ([]*big.Int, error) {
	coeffs := make([]*big.Int, threshold)
	coeffs[0] = big.NewInt(int64(secretByte))
	for i := 1; i < threshold; i++ {
		c, err := rand.Int(rand.Reader, prime)
		if err != nil {
			return nil, fmt.Errorf("random coefficient generation failed: %w", err)
		}
		coeffs[i] = c
	}
	return coeffs, nil
}

func evaluatePolynomial(coeffs []*big.Int, x, prime *big.Int) *big.Int {
	if len(coeffs) == 0 {
		return big.NewInt(0)
	}
	result := new(big.Int).Set(coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, coeffs[i])
		result.Mod(result, prime)
	}
	return result
}

// appendFieldElement appends a field element (assumed to be < 2^16) to the
// backing slice using two bytes (little-endian) to preserve compatibility
// with existing share encoding.
func appendFieldElement(dst []byte, value uint64) []byte {
	return append(dst, byte(value&0xFF), byte((value>>8)&0xFF))
}

// decodeFieldElement decodes the field element at logical byte position
// bytePos from the given share value. It expects each element to occupy
// exactly two bytes and returns (0, false) if out of range.
func decodeFieldElement(src []byte, bytePos int) (int64, bool) {
	idx := bytePos * 2
	if idx+1 >= len(src) {
		return 0, false
	}
	return int64(src[idx]) + int64(src[idx+1])*256, true
}

func lagrangeInterpolate(shares []Share, bytePos int, prime *big.Int) (*big.Int, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares for interpolation")
	}
	if bytePos < 0 {
		return nil, errors.New("invalid byte position")
	}

	result := big.NewInt(0)

	// Each secret byte is stored as two consecutive bytes in the share value.
	for i := range shares {
		yiVal, ok := decodeFieldElement(shares[i].Value, bytePos)
		if !ok {
			return nil, fmt.Errorf("share %d: byte position out of range", i)
		}
		if yiVal >= FieldPrime {
			return nil, fmt.Errorf("share %d: decoded value %d out of field range [0, %d]", i, yiVal, FieldPrime-1)
		}

		xi := big.NewInt(int64(shares[i].Index))
		yi := big.NewInt(yiVal)

		num := big.NewInt(1)
		den := big.NewInt(1)

		for j := range shares {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(shares[j].Index))
			num.Mul(num, new(big.Int).Neg(xj))
			num.Mod(num, prime)
			den.Mul(den, new(big.Int).Sub(xi, xj))
			den.Mod(den, prime)
		}

		invDen := new(big.Int).ModInverse(den, prime)
		if invDen == nil {
			return nil, errors.New("modular inverse does not exist")
		}

		li := new(big.Int).Mul(num, invDen)
		li.Mod(li, prime)
		term := new(big.Int).Mul(yi, li)
		term.Mod(term, prime)
		result.Add(result, term)
		result.Mod(result, prime)
	}

	return result, nil
}
