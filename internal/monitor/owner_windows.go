//go:build windows

package monitor

import "io/fs"

// Windows has no uid; the monitor only installs on macOS, so an unknown owner is never trusted.
func ownerUID(fs.FileInfo) uint32 { return ^uint32(0) }
