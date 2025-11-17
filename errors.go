package charon

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sync"

	"gitlab.com/tozd/go/errors"
)

func callers(extraSkip int) []uintptr {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3+extraSkip, pcs[:]) //nolint:mnd
	return pcs[0:n]
}

// ErrorCode represents the type of the error.
type ErrorCode string

type validationError struct {
	Message   string
	Code      ErrorCode
	stack     []uintptr
	details   map[string]interface{}
	detailsMu *sync.Mutex
}

func (v *validationError) Error() string {
	return v.Message
}

func (v *validationError) Details() map[string]interface{} {
	v.detailsMu.Lock()
	defer v.detailsMu.Unlock()

	if v.details == nil {
		v.details = map[string]interface{}{
			"code": v.Code,
		}
	}
	return v.details
}

func (v *validationError) StackTrace() []uintptr {
	return v.stack
}

func (v *validationError) Format(s fmt.State, verb rune) {
	_, _ = fmt.Fprintf(s, fmt.FormatString(s, verb), errors.Formatter{Error: v})
}

func (v *validationError) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(errors.Formatter{Error: v})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal validationError")
	}
	return b, nil
}

func newValidationError(message string, code ErrorCode) errors.E {
	return &validationError{
		Message:   message,
		Code:      code,
		stack:     callers(0),
		details:   nil,
		detailsMu: new(sync.Mutex),
	}
}
