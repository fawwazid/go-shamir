package goshamir_test

import (
	"testing"

	goshamir "github.com/fawwazid/go-shamir"
)

func TestSplitAndCombineWithThresholdReconstruction(t *testing.T) {
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

func TestEncodeDecodeSharesPreservesSecret(t *testing.T) {
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

func TestSplitEmptySecret(t *testing.T) {
	_, err := goshamir.Split([]byte{}, 5, 3)
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestSplitThresholdTooLow(t *testing.T) {
	_, err := goshamir.Split([]byte("secret"), 5, 1)
	if err == nil {
		t.Fatal("expected error for threshold < 2")
	}

	_, err = goshamir.Split([]byte("secret"), 5, 0)
	if err == nil {
		t.Fatal("expected error for threshold = 0")
	}
}

func TestSplitTotalSharesExceeds255(t *testing.T) {
	_, err := goshamir.Split([]byte("secret"), 256, 3)
	if err == nil {
		t.Fatal("expected error for totalShares > 255")
	}
}

func TestSplitTotalSharesLessThanThreshold(t *testing.T) {
	_, err := goshamir.Split([]byte("secret"), 2, 3)
	if err == nil {
		t.Fatal("expected error when totalShares < threshold")
	}
}

func TestCombineEmptyShares(t *testing.T) {
	_, err := goshamir.Combine([]goshamir.Share{}, 3)
	if err == nil {
		t.Fatal("expected error for empty shares")
	}
}

func TestCombineThresholdTooLow(t *testing.T) {
	shares, _ := goshamir.Split([]byte("secret"), 5, 3)
	_, err := goshamir.Combine(shares[:3], 1)
	if err == nil {
		t.Fatal("expected error for threshold < 2")
	}
}

func TestCombineNotEnoughShares(t *testing.T) {
	shares, _ := goshamir.Split([]byte("secret"), 5, 3)
	_, err := goshamir.Combine(shares[:2], 3)
	if err == nil {
		t.Fatal("expected error when shares < threshold")
	}
}

func TestCombineInconsistentShareLengths(t *testing.T) {
	shares := []goshamir.Share{
		{Index: 1, Value: []byte{1, 2, 3}},
		{Index: 2, Value: []byte{4, 5}},
		{Index: 3, Value: []byte{6, 7, 8}},
	}
	_, err := goshamir.Combine(shares, 3)
	if err == nil {
		t.Fatal("expected error for inconsistent share lengths")
	}
}

func TestCombineZeroShareIndex(t *testing.T) {
	shares := []goshamir.Share{
		{Index: 0, Value: []byte{1, 2, 3}},
		{Index: 2, Value: []byte{4, 5, 6}},
		{Index: 3, Value: []byte{7, 8, 9}},
	}
	_, err := goshamir.Combine(shares, 3)
	if err == nil {
		t.Fatal("expected error for share index = 0")
	}
}

func TestCombineDuplicateShareIndices(t *testing.T) {
	shares := []goshamir.Share{
		{Index: 1, Value: []byte{1, 2, 3}},
		{Index: 1, Value: []byte{4, 5, 6}},
		{Index: 3, Value: []byte{7, 8, 9}},
	}
	_, err := goshamir.Combine(shares, 3)
	if err == nil {
		t.Fatal("expected error for duplicate share indices")
	}
}

func TestDecodeSharesFromHexMalformedString(t *testing.T) {
	// Missing colon separator
	_, err := goshamir.DecodeSharesFromHex([]string{"123abc"})
	if err == nil {
		t.Fatal("expected error for malformed string without colon")
	}
}

func TestDecodeSharesFromHexInvalidIndex(t *testing.T) {
	// Index out of uint8 range
	_, err := goshamir.DecodeSharesFromHex([]string{"256:abc123"})
	if err == nil {
		t.Fatal("expected error for invalid index")
	}

	// Non-numeric index
	_, err = goshamir.DecodeSharesFromHex([]string{"abc:def123"})
	if err == nil {
		t.Fatal("expected error for non-numeric index")
	}
}

func TestDecodeSharesFromHexInvalidHex(t *testing.T) {
	// Invalid hex characters
	_, err := goshamir.DecodeSharesFromHex([]string{"1:ghijkl"})
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestCombineWithMoreThanThresholdShares(t *testing.T) {
	secret := []byte("test secret")
	shares, err := goshamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split error: %v", err)
	}

	// Combine with more shares than threshold
	recovered, err := goshamir.Combine(shares, 3)
	if err != nil {
		t.Fatalf("Combine error: %v", err)
	}
	if string(recovered) != string(secret) {
		t.Fatalf("expected %q, got %q", secret, recovered)
	}
}

func TestSplitFullByteRange(t *testing.T) {
	// Test that all byte values 0-255 are supported
	secret := make([]byte, 256)
	for i := 0; i < 256; i++ {
		secret[i] = byte(i)
	}

	shares, err := goshamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split error for full range secret: %v", err)
	}

	recovered, err := goshamir.Combine(shares[:3], 3)
	if err != nil {
		t.Fatalf("Combine error: %v", err)
	}
	for i := range secret {
		if recovered[i] != secret[i] {
			t.Fatalf("byte %d: expected %d, got %d", i, secret[i], recovered[i])
		}
	}
}
