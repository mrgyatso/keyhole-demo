//go:build !windows && !linux && !darwin

package hostinfo

import (
	"context"
	"errors"
	"runtime"
)

var errUnsupported = errors.New("not supported on " + runtime.GOOS)

func machineID(context.Context) (string, error) { return "", errUnsupported }
func osVersion(context.Context) (string, error) { return "", errUnsupported }
