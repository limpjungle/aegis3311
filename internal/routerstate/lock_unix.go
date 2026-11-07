//go:build unix

package routerstate

import (
	"os"
	"syscall"
)

// lockFile берёт эксклюзивную неблокирующую блокировку; снимается при закрытии файла.
func lockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
