//go:build !unix

package audit

import (
	"errors"
	"os"
)

func lockFile(*os.File) error {
	return errors.New("блокировка файла цепочки не поддерживается на этой платформе")
}
