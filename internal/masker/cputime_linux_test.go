package masker

import (
	"syscall"
	"time"
	"unsafe"
)

// threadCPUTime — CPU-время текущего потока ОС (CLOCK_THREAD_CPUTIME_ID = 3); вызывать под runtime.LockOSThread.
func threadCPUTime() (time.Duration, bool) {
	var ts syscall.Timespec
	if _, _, e := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 3, uintptr(unsafe.Pointer(&ts)), 0); e != 0 {
		return 0, false
	}
	return time.Duration(ts.Nano()), true
}
