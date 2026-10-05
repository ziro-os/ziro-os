package cmd

import (
	"os"
	"syscall"
	"unsafe"
)

const ext4IocResizeFS = 0x40086610 // _IOW('f', 16, __u64)

// resizeFS grows the ext4 filesystem mounted at mnt to blocks, online, with the kernel's
// EXT4_IOC_RESIZE_FS (what resize2fs does for a mounted filesystem), so no e2fsprogs is needed.
var resizeFS = func(mnt string, blocks uint64) error {
	f, err := os.Open(mnt)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), ext4IocResizeFS, uintptr(unsafe.Pointer(&blocks))); e != 0 {
		return e
	}
	return nil
}
