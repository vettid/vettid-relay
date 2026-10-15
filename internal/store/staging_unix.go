//go:build unix

package store

import (
	"errors"
	"os"
	"syscall"
)

const lockingSupported = true

// tryLock takes an exclusive lock on f without waiting; false if another
// process holds it. The lock is freed when f is closed (or its process
// ends).
func tryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}
