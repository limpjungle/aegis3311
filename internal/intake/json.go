package intake

import "github.com/limpjungle/aegis3311/internal/strictjson"

func strictDecode(b []byte, v any) error { return strictjson.Decode(b, v) }
