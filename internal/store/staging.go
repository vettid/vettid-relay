package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Blob bodies are staged (StageBlob) in a folder of this process's own
// next to the database file, .relay-blob-staging-*, holding a lock file
// that the process keeps locked until Close. At Open, folders of other
// processes whose lock is free (the process stopped mid-upload) are
// removed; a folder whose lock is held is another live process's and is
// left alone (on platforms without file locks, other folders are never
// removed).

const (
	stagingPrefix     = ".relay-blob-staging-"
	stagingInitPrefix = ".relay-blob-init-"   // a staging folder not yet locked
	stagePrefix       = ".relay-blob-staged-" // the staged bodies inside it
	stagingLock       = "lock"
)

// openStaging creates this process's staging folder in dir, locks it and
// removes stale ones. The folder is created under another name
// (.relay-blob-init-*), locked, and only then renamed into view, so that
// another process starting at the same time never finds it unlocked.
func openStaging(dir string) (path string, lock *os.File, err error) {
	tmp, err := os.MkdirTemp(dir, stagingInitPrefix)
	if err != nil {
		return "", nil, err
	}
	lock, err = os.OpenFile(filepath.Join(tmp, stagingLock), os.O_CREATE|os.O_RDWR, 0o600)
	if err == nil && lockingSupported {
		if ok, lerr := tryLock(lock); lerr != nil || !ok {
			lock.Close()
			err = errors.Join(os.ErrPermission, lerr)
		}
	}
	if err == nil {
		path = filepath.Join(dir, stagingPrefix+strings.TrimPrefix(filepath.Base(tmp), stagingInitPrefix))
		if err = os.Rename(tmp, path); err != nil {
			lock.Close()
		}
	}
	if err != nil {
		os.RemoveAll(tmp)
		return "", nil, err
	}
	others, _ := filepath.Glob(filepath.Join(dir, stagingPrefix+"*"))
	for _, o := range others {
		if o != path {
			removeIfStale(o)
		}
	}
	// Folders a process left between creating and renaming them.
	inits, _ := filepath.Glob(filepath.Join(dir, stagingInitPrefix+"*"))
	for _, o := range inits {
		if fi, err := os.Stat(o); err == nil && time.Since(fi.ModTime()) > time.Hour {
			os.RemoveAll(o)
		}
	}
	return path, lock, nil
}

// removeIfStale removes another process's staging folder if its lock is
// free (a folder is renamed into view only once locked; one without a
// lock file is removed once an hour old).
func removeIfStale(dir string) {
	f, err := os.OpenFile(filepath.Join(dir, stagingLock), os.O_RDWR, 0)
	if err != nil {
		if fi, serr := os.Stat(dir); serr == nil && time.Since(fi.ModTime()) > time.Hour && lockingSupported {
			os.RemoveAll(dir)
		}
		return
	}
	defer f.Close()
	if ok, err := tryLock(f); err == nil && ok {
		os.RemoveAll(dir)
	}
}

// closeStaging removes this process's staging folder and frees its lock.
func closeStaging(path string, lock *os.File) {
	if lock != nil {
		os.RemoveAll(path)
		lock.Close()
	}
}
