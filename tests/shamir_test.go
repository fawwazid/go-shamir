package goshamir_test

import (
	"testing"

	goshamir "github.com/fawwazid/go-shamir"
)

func TestSplitAndCombine(t *testing.T) {
	secret := []byte("hello shamir")

	shares, err := goshamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split error: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	recovered, err := goshamir.Combine(shares[:3], 3)
	if err != nil {
		t.Fatalf("Combine error: %v", err)
	}
	if string(recovered) != string(secret) {
		t.Fatalf("expected %q, got %q", secret, recovered)
	}
}

func TestEncodeDecodeShares(t *testing.T) {
	secret := []byte("abc")
	shares, err := goshamir.Split(secret, 3, 2)
	if err != nil {
		t.Fatalf("Split error: %v", err)
	}

	encoded := goshamir.EncodeSharesToHex(shares)
	decoded, err := goshamir.DecodeSharesFromHex(encoded)
	if err != nil {
		t.Fatalf("DecodeSharesFromHex error: %v", err)
	}

	recovered, err := goshamir.Combine(decoded[:2], 2)
	if err != nil {
		t.Fatalf("Combine error: %v", err)
	}
	if string(recovered) != string(secret) {
		t.Fatalf("expected %q, got %q", secret, recovered)
	}
}
