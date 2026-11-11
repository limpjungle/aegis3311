package audit

import "testing"

// router_halted/egress_canary допустима только для router_halted; not_sent/egress_canary требует degrade_l1.
func TestRouterHaltedEgressCanary(t *testing.T) {
	e := validEvent("router_halted")
	e.Reason = "egress_canary"
	if err := e.Validate(); err != nil {
		t.Fatalf("router_halted(egress_canary): %v", err)
	}
	for _, reason := range []string{"egress_canary ", "Egress_Canary", "egress-canary", "canary", "egress", "bogus", ""} {
		e := validEvent("router_halted")
		e.Reason = reason
		if err := e.Validate(); err == nil {
			t.Errorf("router_halted(%q) принята", reason)
		}
	}
	for _, kind := range []string{"endpoint_down", "endpoint_up", "endpoint_quarantined", "state_created"} {
		e := validEvent(kind)
		e.Reason = "egress_canary"
		if err := e.Validate(); err == nil {
			t.Errorf("%s с причиной egress_canary принято", kind)
		}
	}
}

func TestNotSentEgressCanary(t *testing.T) {
	const base = "noop_requested_l0"
	r := shadowRecord(t, base)
	notSent("egress_canary")(r)
	r.LLM.DegradeL1 = true // фикстура notSent знает только прежние причины
	if err := r.Validate(); err != nil {
		t.Fatalf("not_sent/egress_canary с degrade_l1: %v", err)
	}
	// degrade_l1 обязателен.
	r2 := shadowRecord(t, base)
	notSent("egress_canary")(r2)
	r2.LLM.DegradeL1 = false
	if err := r2.Validate(); err == nil {
		t.Error("egress_canary без degrade_l1 принят")
	}
	// Без модели и ответа: sent-признаки недопустимы.
	r3 := shadowRecord(t, base)
	notSent("egress_canary")(r3)
	r3.LLM.DegradeL1 = true
	r3.Model = &ModelInfo{Profile: "p", Slug: "s", EndpointRole: "primary", RequestFlags: ProviderFlags{ZDR: true, DataCollection: "deny"}}
	if err := r3.Validate(); err == nil {
		t.Error("egress_canary с model принят")
	}
	// Режим off с этой причиной недопустим.
	r4 := shadowRecord(t, base)
	notSent("egress_canary")(r4)
	r4.LLM.DegradeL1, r4.LLM.Mode = true, "off"
	if err := r4.Validate(); err == nil {
		t.Error("mode=off с egress_canary принят")
	}
	// Неизвестная родственная причина по-прежнему отвергается.
	for _, reason := range []string{"egress_canary2", "canary", "Egress_Canary"} {
		r := shadowRecord(t, base)
		notSent(reason)(r)
		r.LLM.DegradeL1 = true
		if err := r.Validate(); err == nil {
			t.Errorf("not_sent/%s принята", reason)
		}
	}
}
