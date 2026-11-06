// Package catalog содержит машиночитаемые записи каталога действий.
//
// Записи — данные, а не код: их меняют только через ревью по §4 docs/03-autonomy/action-catalog.md.
// Разбор и проверку выполняет internal/catalog.
package catalog

import "embed"

// FS — встроенные записи каталога (catalog/actions/*.yaml).
//
//go:embed actions/*.yaml
var FS embed.FS
