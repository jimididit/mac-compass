//go:build !windows

package monitor

import (
	"io/fs"
	"syscall"
)

func ownerUID(info fs.FileInfo) uint32 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Uid
	}
	return ^uint32(0) // unknown owner is never trusted
}
