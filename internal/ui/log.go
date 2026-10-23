package ui

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"charm.land/log/v2"
)

// NewLogger returns a slog.Logger that writes human-friendly lines through
// charmbracelet/log, or JSON lines when json is set.
func NewLogger(w io.Writer, level string, json bool) (*slog.Logger, error) {
	lv, err := log.ParseLevel(strings.ToLower(level))
	if err != nil {
		return nil, fmt.Errorf("invalid log level %q (use debug, info, warn or error)", level)
	}
	h := log.NewWithOptions(w, log.Options{Level: lv, Prefix: "sarifix"})
	if json {
		h.SetFormatter(log.JSONFormatter)
	}
	return slog.New(h), nil
}
