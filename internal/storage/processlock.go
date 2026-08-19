// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type ProcessLock struct {
	file *os.File
}

// AcquireProcessLock coordinates the long-running server and offline migration
// commands. Servers hold a shared lock; projection rebuilds require exclusive
// ownership and therefore cannot overlap a live server process.
func AcquireProcessLock(root string, exclusive bool) (*ProcessLock, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("process lock root must be absolute and clean")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, errors.New("create process lock root")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("process lock root must be a private non-symlink directory")
	}
	path := filepath.Join(root, "process.lock")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open process lock")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open process lock")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		_ = file.Close()
		return nil, errors.New("process lock must be a regular non-symlink file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("process lock must not have additional hard links")
	}
	operation := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		operation = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if err = syscall.Flock(fd, operation); err != nil {
		_ = file.Close()
		return nil, errors.New("Observatory data directory is active in another process")
	}
	if err = file.Chmod(0o600); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = file.Close()
		return nil, errors.New("secure process lock")
	}
	return &ProcessLock{file: file}, nil
}

func (lock *ProcessLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if err != nil {
		return err
	}
	return closeErr
}
