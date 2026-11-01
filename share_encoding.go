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

// MaxEncodedShareLength bounds a single hex-encoded share.
const MaxEncodedShareLength = 4 + 4*MaxSecretLength

// EncodeSharesToHex converts shares to hex string format "index:hexvalue".
func EncodeSharesToHex(shares []Share) ([]string, error) {
	if shares == nil {
		return nil, ErrNilShares
	}
	if len(shares) > MaxShares {
		return nil, fmt.Errorf("share count must not exceed %d", MaxShares)
	}
	result := make([]string, len(shares))
	indices := make(map[uint8]struct{}, len(shares))
	for i, s := range shares {
		if s.Index == 0 {
			return nil, fmt.Errorf("invalid share at index %d: share index must be non-zero", i)
		}
		if _, exists := indices[s.Index]; exists {
			return nil, fmt.Errorf("invalid share at index %d: duplicate share index", i)
		}
		indices[s.Index] = struct{}{}
		if len(s.Value) == 0 || len(s.Value)%2 != 0 || len(s.Value) > MaxSecretLength*2 {
			return nil, fmt.Errorf("invalid share at index %d: %w", i, ErrInvalidEncodedShare)
		}
		for pos := 0; pos < len(s.Value)/2; pos++ {
			fieldElement, ok := decodeFieldElement(s.Value, pos)
			if !ok || fieldElement >= FieldPrime {
				return nil, fmt.Errorf("invalid share at index %d: %w", i, ErrInvalidEncodedShare)
			}
		}
		result[i] = encodeShareToHex(s)
	}
	return result, nil
}

// DecodeSharesFromHex converts hex-encoded strings back to shares.
func DecodeSharesFromHex(encoded []string) ([]Share, error) {
	if encoded == nil {
		return nil, ErrNilEncoded
	}
	if len(encoded) > MaxShares {
		return nil, ErrInvalidEncodedShare
	}
	shares := make([]Share, len(encoded))
	for i, v := range encoded {
		if len(v) > MaxEncodedShareLength {
			return nil, fmt.Errorf("invalid share at index %d: %w", i, ErrInvalidEncodedShare)
		}
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
	indexText, valueText, ok := strings.Cut(encoded, ":")
	if !ok {
		return Share{}, ErrInvalidEncodedShare
	}

	index, err := strconv.ParseUint(indexText, 10, 8)
	if err != nil {
		return Share{}, ErrInvalidEncodedShare
	}
	if index == 0 {
		return Share{}, ErrInvalidEncodedShare
	}

	value, err := hex.DecodeString(valueText)
	if err != nil {
		return Share{}, ErrInvalidEncodedShare
	}
	if len(value) == 0 || len(value)%2 != 0 || len(value) > MaxSecretLength*2 {
		return Share{}, ErrInvalidEncodedShare
	}
	for pos := 0; pos < len(value)/2; pos++ {
		fieldElement, ok := decodeFieldElement(value, pos)
		if !ok || fieldElement >= FieldPrime {
			return Share{}, ErrInvalidEncodedShare
		}
	}

	return Share{Index: uint8(index), Value: value}, nil
}
