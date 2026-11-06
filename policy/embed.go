// Package policy содержит политики OPA/Rego: матрицу автономности и ограничители PEP.
//
// Политики — данные под ревью (CODEOWNERS). Тестовые файлы (*_test.rego) попадают во FS,
// загрузчик движка их пропускает.
package policy

import "embed"

// FS — встроенные политики (policy/aegis/*/*.rego).
//
//go:embed aegis/*/*.rego
var FS embed.FS
