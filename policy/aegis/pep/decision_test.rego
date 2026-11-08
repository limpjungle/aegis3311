package aegis.pep_test

test_decision_always_defined_on_empty_input if {
	d := data.aegis.pep.decision with input as {}
	d.effective_level == "L0"
	d.ceiling == "L0"
	count(d.deny) > 0
	d.policy_revision == "0.3.0"
}

test_decision_unknown_level if {
	inp := patched([["/level/granted", "L9"]])
	"input_invalid" in deny_codes(inp)
	effective(inp) == "L0"
}

test_decision_missing_flags if {
	inp := object.remove(base, ["flags"])
	"input_invalid" in deny_codes(inp)
	effective(inp) == "L0"
}

test_decision_missing_one_flag if {
	inp := json.remove(base, ["/flags/human_engaged"])
	"input_invalid" in deny_codes(inp)
}

test_decision_clean_allow if {
	d := dec(base)
	d.effective_level == "L3"
	d.ceiling == "L3"
	d.deny == set()
	d.caps == set()
}

test_decision_min_of_caps if {
	inp := patched([["/flags/human_engaged", true], ["/level/granted", "L2"]])
	effective(inp) == "L1"
}

test_decision_granted_below_caps_stays if {
	inp := patched([["/flags/human_engaged", true], ["/level/granted", "L0"]])
	effective(inp) == "L0"
}

test_decision_deny_forces_l0_over_caps if {
	inp := patched([["/target/namespace", "kube-system"], ["/flags/human_engaged", true]])
	effective(inp) == "L0"
}

test_decision_ceiling_reported if {
	inp := patched(array.concat(as_action("workload.restart", "R2", "frozen", "policy"), [["/target/environment", "prod-baremetal"], ["/level/granted", "L1"]]))
	dec(inp).ceiling == "L2"
	effective(inp) == "L1"
}
