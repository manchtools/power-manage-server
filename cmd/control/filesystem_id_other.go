//go:build !linux

package main

import "errors"

// filesystemDeviceID has no portable implementation: control ships only as a
// Linux service, and the separation between the database and the audit archive
// is a property that must be proven rather than assumed. A build for any other
// platform therefore refuses every configuration instead of admitting one whose
// archive may sit on the database's own mount.
func filesystemDeviceID(string) (uint64, error) {
	return 0, errors.New("the filesystem identifier is unavailable on this platform")
}
