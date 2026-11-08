//go:build !linux

package masker

import "time"

// threadCPUTime — на не-Linux CPU-времени потока нет: TestMaskScalesLinearly пропускается.
func threadCPUTime() (time.Duration, bool) { return 0, false }
