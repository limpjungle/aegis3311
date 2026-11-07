package audit

import (
	"bytes"
	"os"
	"testing"
)

// Verify на произвольном вводе не паникует, а принятая цепочка подписана ключом из keyring.
func FuzzVerify(f *testing.F) {
	path, _, k, w := writeChainF(f)
	w.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add(b[:len(b)/2])
	f.Add([]byte("{}\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, in []byte) {
		head, err := Verify(bytes.NewReader(in), k, VerifyOptions{})
		if err == nil && head.Seq > 0 && !bytes.HasPrefix(b, in) {
			// Принять можно только префикс настоящей цепочки по целым строкам: без ключа новую запись не подписать.
			t.Fatalf("принята цепочка, не являющаяся префиксом исходной (seq %d)", head.Seq)
		}
	})
}
