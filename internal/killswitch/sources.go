package killswitch

import (
	"context"

	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
)

// FuncSource — канал, заданный функцией чтения (ConfigMap через kube-клиент intake, тесты).
type FuncSource struct {
	Name string
	F    func(context.Context) ([]byte, error)
}

func (s FuncSource) Channel() string                           { return s.Name }
func (s FuncSource) Fetch(ctx context.Context) ([]byte, error) { return s.F(ctx) }

type s3Source struct{ c *s3.Client }

// S3Source — внешний канал (out-of-band): объект Cfg.Key в S3.
func S3Source(c *s3.Client) Source { return s3Source{c} }

func (s s3Source) Channel() string                           { return "oob" }
func (s s3Source) Fetch(ctx context.Context) ([]byte, error) { return s.c.Get(ctx, s.c.Cfg.Key) }
