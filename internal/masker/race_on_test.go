//go:build race

package masker

// raceEnabled: детектор гонок замедляет код в разы, жёсткие временные пороги не проверяются.
const raceEnabled = true
