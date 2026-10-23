package version

import "testing"

func TestGet(t *testing.T) {
	saved := [3]string{Version, Commit, Date}
	t.Cleanup(func() { Version, Commit, Date = saved[0], saved[1], saved[2] })
	Version, Commit, Date = "v1.2.3", "abc", "2026-10-22"
	if got := Get(); got != (Info{"v1.2.3", "abc", "2026-10-22"}) {
		t.Errorf("ldflags values not used: %+v", got)
	}
	Version, Commit, Date = "dev", "", ""
	if got := Get(); got.Version == "" {
		t.Errorf("empty version: %+v", got)
	}
}
