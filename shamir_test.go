package goshamir

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// --- Split Tests ---

func TestSplit_BasicFunctionality(t *testing.T) {
	secret := []byte("test secret")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(shares) != 5 {
		t.Errorf("Expected 5 shares, got %d", len(shares))
	}

	// Verify each share has correct index and value length.
	for i, share := range shares {
		expectedIndex := uint8(i + 1)
		if share.Index != expectedIndex {
			t.Errorf("Share %d: expected index %d, got %d", i, expectedIndex, share.Index)
		}
		// Each byte becomes 2 bytes (for prime > 256).
		expectedLen := len(secret) * 2
		if len(share.Value) != expectedLen {
			t.Errorf("Share %d: expected value length %d, got %d", i, expectedLen, len(share.Value))
		}
	}
}

func TestSplit_EmptySecret(t *testing.T) {
	_, err := Split([]byte{}, 5, 3)
	if err == nil {
		t.Error("Expected error for empty secret")
	}
}

func TestSplit_ThresholdTooLow(t *testing.T) {
	_, err := Split([]byte("test"), 5, 1)
	if err == nil {
		t.Error("Expected error for threshold < 2")
	}
}

func TestSplit_TotalSharesLessThanThreshold(t *testing.T) {
	_, err := Split([]byte("test"), 2, 5)
	if err == nil {
		t.Error("Expected error when totalShares < threshold")
	}
}

func TestSplit_TotalSharesExceedsMax(t *testing.T) {
	_, err := Split([]byte("test"), 256, 3)
	if err == nil {
		t.Error("Expected error when totalShares > 255")
	}
}

func TestSplit_AllByteValues(t *testing.T) {
	// Test that all byte values [0-255] can be split.
	secret := make([]byte, 256)
	for i := 0; i < 256; i++ {
		secret[i] = byte(i)
	}

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed for full byte range: %v", err)
	}

	recovered, err := Combine(shares[:3], 3)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Error("Recovered secret does not match original for full byte range")
	}
}

// --- Combine Tests ---

func TestCombine_BasicReconstruction(t *testing.T) {
	secret := []byte("hello world")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	recovered, err := Combine(shares[:3], 3)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("Expected %q, got %q", secret, recovered)
	}
}

func TestCombine_DifferentShareSubsets(t *testing.T) {
	secret := []byte("secret data")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Test different combinations of 3 shares.
	subsets := [][]Share{
		{shares[0], shares[1], shares[2]},
		{shares[0], shares[2], shares[4]},
		{shares[1], shares[3], shares[4]},
		{shares[2], shares[3], shares[4]},
	}

	for i, subset := range subsets {
		recovered, err := Combine(subset, 3)
		if err != nil {
			t.Errorf("Subset %d: Combine failed: %v", i, err)
			continue
		}
		if !bytes.Equal(secret, recovered) {
			t.Errorf("Subset %d: Expected %q, got %q", i, secret, recovered)
		}
	}
}

func TestCombine_MoreThanThreshold(t *testing.T) {
	secret := []byte("test")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Provide all 5 shares, should still work.
	recovered, err := Combine(shares, 3)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("Expected %q, got %q", secret, recovered)
	}
}

func TestCombine_InsufficientShares(t *testing.T) {
	secret := []byte("test")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	_, err = Combine(shares[:2], 3)
	if err == nil {
		t.Error("Expected error for insufficient shares")
	}
}

func TestCombine_NoShares(t *testing.T) {
	_, err := Combine([]Share{}, 3)
	if err == nil {
		t.Error("Expected error for empty shares slice")
	}
}

func TestCombine_DuplicateIndices(t *testing.T) {
	shares := []Share{
		{Index: 1, Value: []byte{1, 0}},
		{Index: 1, Value: []byte{2, 0}},
		{Index: 2, Value: []byte{3, 0}},
	}
	_, err := Combine(shares, 3)
	if err == nil {
		t.Error("Expected error for duplicate indices")
	}
}

func TestCombine_ZeroIndex(t *testing.T) {
	shares := []Share{
		{Index: 0, Value: []byte{1, 0}},
		{Index: 1, Value: []byte{2, 0}},
		{Index: 2, Value: []byte{3, 0}},
	}
	_, err := Combine(shares, 3)
	if err == nil {
		t.Error("Expected error for zero index")
	}
}

func TestCombine_InconsistentLengths(t *testing.T) {
	shares := []Share{
		{Index: 1, Value: []byte{1, 0, 2, 0}},
		{Index: 2, Value: []byte{3, 0}},
		{Index: 3, Value: []byte{4, 0, 5, 0}},
	}
	_, err := Combine(shares, 3)
	if err == nil {
		t.Error("Expected error for inconsistent share lengths")
	}
}

// --- Encoding Tests ---

func TestEncodeDecode_RoundTrip(t *testing.T) {
	secret := []byte("encoding test")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	encoded, err := EncodeSharesToHex(shares)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if len(encoded) != 5 {
		t.Errorf("Expected 5 encoded strings, got %d", len(encoded))
	}

	decoded, err := DecodeSharesFromHex(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Verify decoded shares match original.
	for i := range shares {
		if shares[i].Index != decoded[i].Index {
			t.Errorf("Share %d: index mismatch", i)
		}
		if !bytes.Equal(shares[i].Value, decoded[i].Value) {
			t.Errorf("Share %d: value mismatch", i)
		}
	}

	// Reconstruct from decoded shares.
	recovered, err := Combine(decoded[:3], 3)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("Expected %q, got %q", secret, recovered)
	}
}

func TestDecode_InvalidFormat(t *testing.T) {
	invalidInputs := []string{
		"invalid",    // No colon
		":abc123",    // No index
		"256:abc123", // Index out of range
		"1:xyz",      // Invalid hex
		"abc:123456", // Non-numeric index
	}

	for _, input := range invalidInputs {
		_, err := DecodeSharesFromHex([]string{input})
		if err == nil {
			t.Errorf("Expected error for input %q", input)
		}
	}
}

// --- Edge Cases ---

func TestSplitCombine_SingleByte(t *testing.T) {
	secret := []byte{42}
	shares, err := Split(secret, 3, 2)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	recovered, err := Combine(shares[:2], 2)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("Expected %v, got %v", secret, recovered)
	}
}

func TestSplitCombine_LargeSecret(t *testing.T) {
	secret := make([]byte, 1024)
	_, err := rand.Read(secret)
	if err != nil {
		t.Fatalf("Failed to generate random secret: %v", err)
	}

	shares, err := Split(secret, 10, 5)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	recovered, err := Combine(shares[:5], 5)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Error("Recovered secret does not match original for large secret")
	}
}

func TestSplitCombine_MinimumThreshold(t *testing.T) {
	secret := []byte("minimum threshold test")
	shares, err := Split(secret, 3, 2)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	recovered, err := Combine(shares[:2], 2)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("Expected %q, got %q", secret, recovered)
	}
}

func TestSplitCombine_MaxShares(t *testing.T) {
	secret := []byte("max shares")
	shares, err := Split(secret, 255, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(shares) != 255 {
		t.Errorf("Expected 255 shares, got %d", len(shares))
	}

	recovered, err := Combine(shares[:3], 3)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("Expected %q, got %q", secret, recovered)
	}
}

// --- Benchmark Tests ---

func BenchmarkSplit(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Split(secret, 5, 3)
	}
}

func BenchmarkCombine(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)
	shares, _ := Split(secret, 5, 3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Combine(shares[:3], 3)
	}
}

func BenchmarkEncode(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)
	shares, _ := Split(secret, 5, 3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeSharesToHex(shares)
	}
}
