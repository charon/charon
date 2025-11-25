package charon

import (
	"fmt"
	"runtime"
	"sync"

	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
)

// TODO: This was copied from gitlab.com/tozd/go/errors. Maybe it should be made public there?
func callers(extraSkip int) []uintptr {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3+extraSkip, pcs[:]) //nolint:mnd
	return pcs[0:n]
}

type validationError struct {
	Message   string
	Code      ErrorCode
	err       error
	stack     []uintptr
	details   map[string]interface{}
	detailsMu *sync.Mutex
}

func (v *validationError) Error() string {
	return v.Message
}

func (v *validationError) Unwrap() error {
	return v.err
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
	return x.Marshal(errors.Formatter{Error: v})
}

func newValidationError(message string, code ErrorCode) errors.E {
	return &validationError{
		Message:   message,
		Code:      code,
		err:       nil,
		stack:     callers(0),
		details:   nil,
		detailsMu: new(sync.Mutex),
	}
}

func toValidationError(err error, code ErrorCode) errors.E {
	if err == nil {
		return nil
	}

	ve := &validationError{
		Message:   err.Error(),
		Code:      code,
		err:       err,
		stack:     nil,
		details:   nil,
		detailsMu: new(sync.Mutex),
	}

	type stackTracer interface {
		StackTrace() []uintptr
	}
	if st, ok := err.(stackTracer); ok {
		// If err is errors.E, we just copy its stack trace.
		// Otherwise, even if errors.E is wrapped somewhere inside,
		// we record a new stack trace.
		ve.stack = st.StackTrace()
	} else {
		ve.stack = callers(0)
	}

	return ve
}
