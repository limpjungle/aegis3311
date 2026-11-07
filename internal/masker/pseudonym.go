package masker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

const (
	secretRepl = "<SECRET_REMOVED>"
	cardRepl   = "<CARD>"
)

// incidentKey — ключ псевдонимов инцидента: HMAC-SHA256(master, "aegis/masker/v1\x00"+incidentID). Не кэшируется.
func incidentKey(master []byte, incidentID string) []byte {
	h := hmac.New(sha256.New, master)
	h.Write([]byte("aegis/masker/v1\x00" + incidentID))
	return h.Sum(nil)
}

// pseudonym — "<KIND_xxxxxxxx>": 8 hex от HMAC(ключ инцидента, kind+"\x00"+normalized).
func pseudonym(inc []byte, kind, normalized string) string {
	h := hmac.New(sha256.New, inc)
	h.Write([]byte(kind + "\x00" + normalized))
	return "<" + kind + "_" + hex.EncodeToString(h.Sum(nil))[:8] + ">"
}
