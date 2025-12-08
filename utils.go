package goshamir

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidEncodedShare is returned when a share string cannot be parsed
// due to invalid format, non-hex characters, or out-of-range index values.
var ErrInvalidEncodedShare = errors.New("invalid encoded share format")

// ErrNilShares is returned when a nil share slice is provided to EncodeSharesToHex.
var ErrNilShares = errors.New("shares cannot be nil")

// ErrNilEncoded is returned when a nil encoded slice is provided to DecodeSharesFromHex.
var ErrNilEncoded = errors.New("encoded data cannot be nil")

// EncodeSharesToHex converts shares to hex string format "index:hexvalue".
func EncodeSharesToHex(shares []Share) ([]string, error) {
	if shares == nil {
		return nil, ErrNilShares
	}
	if len(shares) == 0 {
		return []string{}, nil
	}
	result := make([]string, len(shares))
	for i, s := range shares {
		result[i] = encodeShareToHex(s)
	}
	return result, nil
}

// DecodeSharesFromHex converts hex-encoded strings back to shares.
func DecodeSharesFromHex(encoded []string) ([]Share, error) {
	if encoded == nil {
		return nil, ErrNilEncoded
	}
	if len(encoded) == 0 {
		return []Share{}, nil
	}
	shares := make([]Share, len(encoded))
	for i, v := range encoded {
		share, err := decodeShareFromHex(v)
		if err != nil {
			return nil, fmt.Errorf("invalid share at index %d: %w", i, err)
		}
		shares[i] = share
	}
	return shares, nil
}

func encodeShareToHex(s Share) string {
	return strconv.FormatUint(uint64(s.Index), 10) + ":" + hex.EncodeToString(s.Value)
}

func decodeShareFromHex(encoded string) (Share, error) {
	if encoded == "" {
		return Share{}, ErrInvalidEncodedShare
	}
	parts := strings.SplitN(encoded, ":", 2)
	if len(parts) != 2 {
		return Share{}, ErrInvalidEncodedShare
	}
	if parts[0] == "" || parts[1] == "" {
		return Share{}, ErrInvalidEncodedShare
	}

	index, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return Share{}, ErrInvalidEncodedShare
	}
	if index == 0 {
		return Share{}, ErrInvalidEncodedShare
	}

	value, err := hex.DecodeString(parts[1])
	if err != nil {
		return Share{}, ErrInvalidEncodedShare
	}
	if len(value) == 0 {
		return Share{}, ErrInvalidEncodedShare
	}

	return Share{Index: uint8(index), Value: value}, nil
}

// validateSplitParams validates parameters for Split.
func validateSplitParams(secret []byte, totalShares, threshold int) error {
	if secret == nil {
		return errors.New("secret cannot be nil")
	}
	if len(secret) == 0 {
		return errors.New("secret must not be empty")
	}
	if threshold < MinThreshold {
		return fmt.Errorf("threshold must be at least %d", MinThreshold)
	}
	if threshold > MaxShares {
		return fmt.Errorf("threshold must be <= %d", MaxShares)
	}
	if totalShares < threshold {
		return errors.New("totalShares must be >= threshold")
	}
	if totalShares > MaxShares {
		return fmt.Errorf("totalShares must be <= %d", MaxShares)
	}
	return nil
}

// validateCombineParams validates parameters for Combine.
func validateCombineParams(shares []Share, threshold int) error {
	if shares == nil {
		return errors.New("shares cannot be nil")
	}
	if len(shares) == 0 {
		return errors.New("no shares provided")
	}
	if threshold < MinThreshold {
		return fmt.Errorf("threshold must be at least %d", MinThreshold)
	}
	if threshold > MaxShares {
		return fmt.Errorf("threshold must be <= %d", MaxShares)
	}
	if len(shares) < threshold {
		return errors.New("insufficient shares: need at least threshold shares")
	}

	// Only validate the first threshold shares since those are the ones that will be used
	usedShares := shares
	if len(shares) > threshold {
		usedShares = shares[:threshold]
	}

	expectedLen := len(usedShares[0].Value)
	if expectedLen == 0 {
		return errors.New("share value cannot be empty")
	}
	if expectedLen%2 != 0 {
		return errors.New("share value length must be even")
	}
	for i, s := range usedShares {
		if len(s.Value) != expectedLen {
			return fmt.Errorf("share %d has inconsistent length", i)
		}
	}
	return nil
}

// validateShareIndices checks that share indices are non-zero and unique.
func validateShareIndices(shares []Share) error {
	indices := make(map[uint8]bool, len(shares))
	for _, s := range shares {
		if s.Index == 0 {
			return errors.New("share index must be non-zero")
		}
		if indices[s.Index] {
			return errors.New("duplicate share index found")
		}
		indices[s.Index] = true
	}
	return nil
}
