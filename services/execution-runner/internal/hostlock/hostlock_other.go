//go:build !linux

package hostlock

import (
	"errors"
	"os"
)

func acquirePlatformLock(string, string) (*Lock, error) {
	return nil, ErrUnsupported
}

func releasePlatformLock(_ *os.File, _ string) error {
	return ErrUnsupported
}
