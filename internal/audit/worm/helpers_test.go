package worm

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/limpjungle/aegis3311/internal/audit"
)

func ed25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func mkEvent(i int) audit.RouterEvent {
	return audit.RouterEvent{
		Schema: audit.RouterEventSchema, EventID: audit.NewEventID(), RecordedAt: audit.Timestamp(t0),
		Kind: "endpoint_down", Endpoint: "inceptron-fp8", Role: "primary", Reason: "consecutive_failures",
		ConsecutiveFailures: 3, Model: "z-ai/glm-5.3-flash-20260826",
		Initiator: audit.Actor{Kind: "system", ID: "llm-router-1"},
	}
}
