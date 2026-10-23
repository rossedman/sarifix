package testutil

import (
	"encoding/json"
	"testing"
)

func TestLargeSARIF(t *testing.T) {
	t.Parallel()
	data := LargeSARIF(64 << 10)
	if len(data) < 64<<10 {
		t.Fatalf("only %d bytes", len(data))
	}
	var doc struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Runs[0].Results) == 0 {
		t.Fatalf("invalid JSON: %v", err)
	}
}
