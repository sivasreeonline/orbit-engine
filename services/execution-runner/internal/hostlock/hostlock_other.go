//go:build !linux

package hostlock

import "errors"

func acquirePlatformLock(string, string) (*Lock, error) {
	return nil, ErrUnsupported
}

func releasePlatformLock(_ interface{ Close() error }, _ string) error {
	return ErrUnsupported
}
