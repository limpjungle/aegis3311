package pyjson

import "testing"

// Ожидаемые строки получены из Python 3: json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":")) и json.dumps(v).
var pyCases = []struct{ in, canonical, pydefault string }{
	{"{\"b\":1,\"a\":[1.0,2.5,-0.0,0,-0,1e16,1e-5,0.0001,123456789012345678901234567890,1.7976931348623157e308,5e-324,0.1,100.0,1e15,12345678901234567.0,3.14159,2.5e-7,1E3]}", "{\"a\":[1.0,2.5,-0.0,0,0,1e+16,1e-05,0.0001,123456789012345678901234567890,1.7976931348623157e+308,5e-324,0.1,100.0,1000000000000000.0,1.2345678901234568e+16,3.14159,2.5e-07,1000.0],\"b\":1}", "{\"b\": 1, \"a\": [1.0, 2.5, -0.0, 0, 0, 1e+16, 1e-05, 0.0001, 123456789012345678901234567890, 1.7976931348623157e+308, 5e-324, 0.1, 100.0, 1000000000000000.0, 1.2345678901234568e+16, 3.14159, 2.5e-07, 1000.0]}"},
	{"{\"s\":\"привет \\\"q\\\" \\\\ \\n\\t\\r\\b\\f \\u0001 \\u007f <>&/ \\u2028 😀 é\",\"я\":1,\"Z\":2,\"a\":3,\"ä\":4,\"😀\":5,\"\\uffff\":6}", "{\"Z\":2,\"a\":3,\"s\":\"привет \\\"q\\\" \\\\ \\n\\t\\r\\b\\f \\u0001  <>&/   😀 é\",\"ä\":4,\"я\":1,\"￿\":6,\"😀\":5}", "{\"s\": \"\\u043f\\u0440\\u0438\\u0432\\u0435\\u0442 \\\"q\\\" \\\\ \\n\\t\\r\\b\\f \\u0001 \\u007f <>&/ \\u2028 \\ud83d\\ude00 \\u00e9\", \"\\u044f\": 1, \"Z\": 2, \"a\": 3, \"\\u00e4\": 4, \"\\ud83d\\ude00\": 5, \"\\uffff\": 6}"},
	{"[true,false,null,{},[],\"\",{\"x\":{\"z\":1,\"y\":[{\"b\":0,\"a\":0}]}}]", "[true,false,null,{},[],\"\",{\"x\":{\"y\":[{\"a\":0,\"b\":0}],\"z\":1}}]", "[true, false, null, {}, [], \"\", {\"x\": {\"z\": 1, \"y\": [{\"b\": 0, \"a\": 0}]}}]"},
}

func TestMatchesPython(t *testing.T) {
	for i, c := range pyCases {
		v, err := Parse([]byte(c.in))
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if got := string(Marshal(v, Canonical)); got != c.canonical {
			t.Errorf("%d canonical:\n got %s\nwant %s", i, got, c.canonical)
		}
		if got := string(Marshal(v, PyDefault)); got != c.pydefault {
			t.Errorf("%d default:\n got %s\nwant %s", i, got, c.pydefault)
		}
	}
}

func TestRejects(t *testing.T) {
	for _, in := range []string{`{"a":1,"a":2}`, `1e400`, `[1] 2`, "\"\xff\"", `{"a":NaN}`, ``} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("принято %q", in)
		}
	}
}

func TestFloatRepr(t *testing.T) {
	for f, want := range map[float64]string{1: "1.0", 1e16: "1e+16", 1e-5: "1e-05", 0.0001: "0.0001", 1e100: "1e+100", 123.456: "123.456", -2.5e-10: "-2.5e-10"} {
		if got := FloatRepr(f); got != want {
			t.Errorf("FloatRepr(%v) = %s, want %s", f, got, want)
		}
	}
}
