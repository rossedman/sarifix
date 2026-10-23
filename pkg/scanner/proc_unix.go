//go:build unix

package scanner

import (
	"os/exec"
	"syscall"
)

// isolate puts the command in its own process group and makes cancellation
// kill the whole group, so a timed-out scanner's children die with it.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
