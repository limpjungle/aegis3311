// Package goldensynthetic встраивает в Go-код файлы eval-контура, от которых зависит воспроизводимость:
// конфигурацию endpoint'ов, системный промпт и схему ответа. LLM-роутер берёт их отсюда, чтобы отправлять
// в модель то же, на чём модель прошла eval. Источник истины — файлы этого каталога и data/manifest.json.
package goldensynthetic

import "embed"

//go:embed profiles.json data/manifest.json prompt/*.md schema/*.json
var FS embed.FS
