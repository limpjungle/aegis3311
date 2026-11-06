package pep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// canonicalJSON — json.Marshal структур с фиксированным порядком полей; map сериализуются с отсортированными ключами,
// числа только целые, поэтому результат не зависит от порядка ключей исходного JSON.
func canonicalJSON(v any) ([]byte, error) { return json.Marshal(v) }

// inputDigest — sha256 канонического JSON {proposal, context}.
func inputDigest(p Proposal, c Context) string {
	b, err := canonicalJSON(struct {
		Proposal Proposal `json:"proposal"`
		Context  Context  `json:"context"`
	}{p, c})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
