package goshamir

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// ErrInvalidEncodedShare indicates an invalid encoded share format.
var ErrInvalidEncodedShare = errors.New("invalid encoded share format")

// EncodeSharesToHex converts a list of shares into a hex string
// representation that is easy to store or transmit.
//
// Format: "index:hexvalue" for each share.
func EncodeSharesToHex(shares []Share) []string {
	result := make([]string, len(shares))
	for i, s := range shares {
		result[i] = encodeSingleShareToHex(s)
	}
	return result
}

// DecodeSharesFromHex converts a list of encoded strings produced by
// EncodeSharesToHex back into []Share.
func DecodeSharesFromHex(data []string) ([]Share, error) {
	shares := make([]Share, len(data))
	for i, v := range data {
		share, err := decodeSingleShareFromHex(v)
		if err != nil {
			return nil, err
		}
		shares[i] = share
	}
	return shares, nil
}

// encodeSingleShareToHex converts a single share into "index:hex".
// The index is encoded as a base-10 integer for readability.
func encodeSingleShareToHex(s Share) string {
	return strconv.Itoa(int(s.Index)) + ":" + hex.EncodeToString(s.Value)
}

// decodeSingleShareFromHex performs the inverse of encodeSingleShareToHex.
func decodeSingleShareFromHex(v string) (Share, error) {
	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return Share{}, ErrInvalidEncodedShare
	}

	idx64, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return Share{}, ErrInvalidEncodedShare
	}

	bytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return Share{}, ErrInvalidEncodedShare
	}

	return Share{Index: uint8(idx64), Value: bytes}, nil
}
