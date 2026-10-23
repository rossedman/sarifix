//go:build !unix

package scanner

import "os/exec"

// isolate is a no-op where process groups are unavailable; cancellation
// kills only the direct child and WaitDelay bounds the wait.
func isolate(*exec.Cmd) {}
