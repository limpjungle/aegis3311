//go:build !unix

package routerstate

import (
	"errors"
	"os"
)

func lockFile(*os.File) error {
	return errors.New("блокировка хранилища не поддерживается на этой платформе")
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
