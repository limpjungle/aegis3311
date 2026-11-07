//go:build unix

package audit

import (
	"os"
	"syscall"
)

// lockFile берёт эксклюзивную неблокирующую блокировку; снимается при закрытии файла.
func lockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
