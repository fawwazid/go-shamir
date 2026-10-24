package goshamir

import (
	"crypto/fips140"
	"errors"
	"testing"
)

func TestFIPSPolicy(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("requires FIPS mode")
	}
	for _, operation := range []func() error{
		func() error { _, err := Split([]byte("secret"), 3, 2); return err },
		func() error { _, err := Combine(nil, 2); return err },
	} {
		if err := operation(); !errors.Is(err, ErrFIPSUnsupported) {
			t.Fatalf("operation error = %v", err)
		}
	}
}
