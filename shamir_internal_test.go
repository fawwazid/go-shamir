package goshamir

import (
	"testing"
)

// TestDivisionByZero tests that the div function returns an error when dividing by zero.
// This tests the defensive error handling added to replace the previous panic behavior.
func TestDivisionByZero(t *testing.T) {
	// Test division by zero with non-zero numerator
	_, err := div(5, 0)
	if err == nil {
		t.Fatal("expected error when dividing by zero")
	}
	if err.Error() != "division by zero in GF(2^8)" {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Test division by zero with zero numerator (should return 0 without error)
	result, err := div(0, 0)
	if err != nil {
		t.Fatalf("unexpected error for 0/0: %v", err)
	}
	if result != 0 {
		t.Fatalf("expected 0 for 0/0, got %d", result)
	}
}

// TestDivNormalCases tests normal division operations in GF(2^8)
func TestDivNormalCases(t *testing.T) {
	// Test that dividing by 1 returns the same value
	for i := uint8(1); i < 10; i++ {
		result, err := div(i, 1)
		if err != nil {
			t.Fatalf("unexpected error for %d/1: %v", i, err)
		}
		if result != i {
			t.Fatalf("expected %d for %d/1, got %d", i, i, result)
		}
	}

	// Test that a/a = 1 for non-zero a
	for i := uint8(1); i < 10; i++ {
		result, err := div(i, i)
		if err != nil {
			t.Fatalf("unexpected error for %d/%d: %v", i, i, err)
		}
		if result != 1 {
			t.Fatalf("expected 1 for %d/%d, got %d", i, i, result)
		}
	}

	// Test that 0/a = 0 for non-zero a
	for i := uint8(1); i < 10; i++ {
		result, err := div(0, i)
		if err != nil {
			t.Fatalf("unexpected error for 0/%d: %v", i, err)
		}
		if result != 0 {
			t.Fatalf("expected 0 for 0/%d, got %d", i, result)
		}
	}
}
