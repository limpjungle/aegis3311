package kube

import (
	"context"
	"net/url"
	"strconv"

	"github.com/limpjungle/aegis3311/internal/intake"
	"github.com/limpjungle/aegis3311/internal/intake/httpget"
)

// listCap — потолок одного листа: размер страницы (limit), объектов всего и страниц всего. PageSize подобран так,
// чтобы страница помещалась в httpget.MaxBytesKube; MaxPages — чтобы весь лист укладывался в request_timeout.
type listCap struct{ PageSize, MaxItems, MaxPages int }

var (
	capPods         = listCap{PageSize: 100, MaxItems: 1000, MaxPages: 20} // спеки подов тяжёлые (env, volumes)
	capEvents       = listCap{PageSize: 250, MaxItems: 1000, MaxPages: 8}
	capReplicaSets  = listCap{PageSize: 100, MaxItems: 500, MaxPages: 10}
	capAnalysisRuns = listCap{PageSize: 50, MaxItems: 200, MaxPages: 8} // measurements раздувают объект
	capPDBs         = listCap{PageSize: 100, MaxItems: 500, MaxPages: 10}
)

type listPage[T any] struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []T `json:"items"`
}

// list читает лист постранично (limit/continue), не больше lc.MaxItems объектов и lc.MaxPages страниц. truncated —
// потолок достигнут, а сервер сообщил о продолжении (или прислал лишнее). Ошибка любой страницы — ошибка листа;
// 410 (истёкший continue) — http_410 без повтора. resourceVersion не задаётся: чанки консистентны по первой странице.
func list[T any](ctx context.Context, c *httpget.Client, path string, q url.Values, lc listCap) (items []T, truncated bool, err error) {
	cont := ""
	for page := 0; page < lc.MaxPages; page++ {
		qq := url.Values{}
		for k, v := range q {
			qq[k] = append([]string(nil), v...)
		}
		qq.Set("limit", strconv.Itoa(lc.PageSize))
		if cont != "" {
			qq.Set("continue", cont)
		}
		var p listPage[T]
		if err := c.GetJSON(ctx, path, qq, &p); err != nil {
			return nil, false, err
		}
		items = append(items, p.Items...)
		cont = p.Metadata.Continue
		if len(items) >= lc.MaxItems {
			return items[:lc.MaxItems], len(items) > lc.MaxItems || cont != "", nil
		}
		if cont == "" {
			return items, false, nil
		}
	}
	// страницы кончились, а сервер сообщает о продолжении (в т.ч. петля токенов и пустые страницы с continue)
	return items, true, nil
}

func truncErr(t bool) error {
	if t {
		return intake.ErrTruncated
	}
	return nil
}
