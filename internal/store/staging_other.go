//go:build !unix

package store

import "os"

const lockingSupported = false

// tryLock: without file locks, another process's folder is never taken
// for stale (removeIfStale removes nothing), and one's own is "locked".
func tryLock(f *os.File) (bool, error) { return false, nil }
