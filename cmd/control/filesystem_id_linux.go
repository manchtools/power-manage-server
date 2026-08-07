//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

// filesystemDeviceID reports the kernel's device identifier for the filesystem
// holding path. Two paths reporting the same identifier are on the same mount,
// which is the condition the audit archive must not be in.
//
// It fails closed: a path that cannot be stat'ed, or whose stat carries no
// device identifier, yields an error rather than an identifier that would
// compare unequal to everything and quietly satisfy the separation check.
func filesystemDeviceID(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	raw, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%q: the filesystem identifier is unavailable", path)
	}
	return uint64(raw.Dev), nil
}
