package goshamir

import (
	"crypto/fips140"
	"errors"
)

// ErrFIPSUnsupported reports an operation outside the approved module boundary.
// These operations are disabled whenever Go's FIPS mode is enabled, including
// fips140=on, which by itself does not reject every non-approved operation.
var ErrFIPSUnsupported = errors.New("go-shamir: operation is not supported in FIPS mode")

func checkNonFIPSOperation() error {
	if fips140.Enabled() {
		return ErrFIPSUnsupported
	}
	return nil
}
