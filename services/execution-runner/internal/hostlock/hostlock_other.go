//go:build !linux

package hostlock

import (
	"os"
)

func acquirePlatformLock(string, string) (*Lock, error) {
	return nil, ErrUnsupported
}

func releasePlatformLock(_ *os.File, _ string) error {
	return ErrUnsupported
}
