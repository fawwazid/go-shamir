package goshamir

import (
	"errors"
	"testing"
)

func TestSplitResourceBounds(t *testing.T) {
	if _, err := Split([]byte{1}, MaxShares, MaxThreshold+1); err == nil {
		t.Fatal("Split accepted threshold above MaxThreshold")
	}
	if _, err := Split(make([]byte, MaxSecretLength+1), 3, 2); err == nil {
		t.Fatal("Split accepted secret above MaxSecretLength")
	}
	shares, err := Split([]byte{42}, MaxThreshold, MaxThreshold)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := Combine(shares, MaxThreshold)
	if err != nil || len(secret) != 1 || secret[0] != 42 {
		t.Fatalf("maximum threshold reconstruction = %v, %v", secret, err)
	}
}

func TestCombineAndEncodingResourceBounds(t *testing.T) {
	tooMany := make([]Share, MaxShares+1)
	if _, err := Combine(tooMany, MinThreshold); err == nil {
		t.Fatal("Combine accepted too many shares")
	}
	if _, err := DecodeSharesFromHex(make([]string, MaxShares+1)); !errors.Is(err, ErrInvalidEncodedShare) {
		t.Fatalf("DecodeSharesFromHex() error = %v, want ErrInvalidEncodedShare", err)
	}
	if _, err := EncodeSharesToHex([]Share{{Index: 1, Value: []byte{1, 1}}}); !errors.Is(err, ErrInvalidEncodedShare) {
		t.Fatalf("EncodeSharesToHex() error = %v, want ErrInvalidEncodedShare", err)
	}
	if _, err := DecodeSharesFromHex([]string{"1:0101"}); !errors.Is(err, ErrInvalidEncodedShare) {
		t.Fatalf("DecodeSharesFromHex() error = %v, want ErrInvalidEncodedShare", err)
	}
}
