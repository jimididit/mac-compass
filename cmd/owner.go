package cmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// chownToInvoker hands files written under sudo back to the user who ran sudo, so they can open their
// own reports and bundles. Permissions are left as written (private to that user). It does nothing
// unless the process is root and sudo told us who called it.
func chownToInvoker(paths ...string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid <= 0 {
		return nil
	}
	for _, root := range paths {
		if root == "" {
			continue
		}
		err := filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(p, uid, gid)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
