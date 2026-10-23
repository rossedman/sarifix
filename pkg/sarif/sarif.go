// Package sarif loads, validates, merges and normalizes SARIF 2.1.0 logs.
//
// It wraps github.com/owenrumney/go-sarif for the object model and schema.
// Loading is forgiving by design: a file that is not JSON, or a run that fails
// schema validation, produces a warning and is skipped, so one broken scanner
// never stops the rest of the pipeline.
package sarif

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	v210 "github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

// Version is the only SARIF version sarifix reads and writes.
const Version = "2.1.0"

// SchemaURI is written to the $schema property of logs sarifix produces.
const SchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

// Re-exported go-sarif types, so callers depend on this package only.
type (
	// Report is a whole SARIF log.
	Report = v210.Report
	// Run is one tool invocation inside a log.
	Run = v210.Run
	// Result is one finding inside a run.
	Result = v210.Result
	// ReportingDescriptor describes a rule.
	ReportingDescriptor = v210.ReportingDescriptor
	// Location is a result location.
	Location = v210.Location
	// ArtifactLocation is a URI plus optional base ID.
	ArtifactLocation = v210.ArtifactLocation
)

// Log is a set of runs loaded from one or more SARIF files. Each run keeps
// the file it came from so warnings and reports can point at it.
type Log struct {
	Runs []*SourcedRun
}

// SourcedRun is a run together with the file it was read from.
//
// The run's original JSON is kept and is what gets written back out:
// go-sarif's structs serialize zero values (an empty "language", a rule's
// "enabled": false, "rank": 0) that would change the log's meaning. Changes
// sarifix makes are recorded as patches and applied to the original JSON.
type SourcedRun struct {
	Run    *Run
	Source string
	Index  int

	raw          json.RawMessage
	fingerprints map[int]map[string]string
}

// AddPartialFingerprint records partialFingerprints[key] = value on result
// i, applied when the run is written.
func (r *SourcedRun) AddPartialFingerprint(i int, key, value string) {
	if r.fingerprints == nil {
		r.fingerprints = map[int]map[string]string{}
	}
	if r.fingerprints[i] == nil {
		r.fingerprints[i] = map[string]string{}
	}
	r.fingerprints[i][key] = value
	if i >= 0 && i < len(r.Run.Results) && r.Run.Results[i] != nil {
		res := r.Run.Results[i]
		if res.PartialFingerprints == nil {
			res.PartialFingerprints = map[string]string{}
		}
		res.PartialFingerprints[key] = value
	}
}

// JSON returns the run's original JSON with recorded patches applied.
func (r *SourcedRun) JSON() (json.RawMessage, error) {
	if len(r.fingerprints) == 0 {
		return r.raw, nil
	}
	dec := json.NewDecoder(bytes.NewReader(r.raw))
	dec.UseNumber()
	var run map[string]any
	if err := dec.Decode(&run); err != nil {
		return nil, err
	}
	results, _ := run["results"].([]any)
	for i, fps := range r.fingerprints {
		if i < 0 || i >= len(results) {
			continue
		}
		res, ok := results[i].(map[string]any)
		if !ok {
			continue
		}
		pf, _ := res["partialFingerprints"].(map[string]any)
		if pf == nil {
			pf = map[string]any{}
		}
		for k, v := range fps {
			pf[k] = v
		}
		res["partialFingerprints"] = pf
	}
	return marshal(run)
}

// Driver returns the run's tool.driver.name, or "" when absent.
func (r *SourcedRun) Driver() string {
	return DriverName(r.Run)
}

// DriverName returns run.tool.driver.name, or "" when absent.
func DriverName(run *Run) string {
	if run == nil || run.Tool == nil || run.Tool.Driver == nil || run.Tool.Driver.Name == nil {
		return ""
	}
	return *run.Tool.Driver.Name
}

// Warning is a non-fatal problem found while loading.
type Warning struct {
	Source string
	Run    int // -1 when the warning is about the whole file
	Msg    string
}

// String formats the warning for logs.
func (w Warning) String() string {
	if w.Run < 0 {
		return fmt.Sprintf("%s: %s", w.Source, w.Msg)
	}
	return fmt.Sprintf("%s: run %d: %s", w.Source, w.Run, w.Msg)
}

// ErrNoFiles is returned by LoadGlobs when no pattern matches a file.
var ErrNoFiles = errors.New("no SARIF files matched")

// envelope is the minimal top-level shape decoded before validation.
type envelope struct {
	Version string            `json:"version"`
	Runs    []json.RawMessage `json:"runs"`
}

// Options control loading.
type Options struct {
	// SkipValidation turns off JSON-schema validation of each run. Structural
	// checks (valid JSON, version, a tool driver name) still apply.
	SkipValidation bool
}

// LoadGlobs expands each pattern and loads every matching file. Patterns that
// name an existing file are used as is. Files are loaded in sorted order and
// each file is loaded once.
func LoadGlobs(patterns []string, opts Options) (*Log, []Warning, error) {
	files, err := Expand(patterns)
	if err != nil {
		return nil, nil, err
	}
	log := &Log{}
	var warns []Warning
	for _, f := range files {
		l, w, err := LoadFile(f, opts)
		warns = append(warns, w...)
		if err != nil {
			warns = append(warns, Warning{Source: f, Run: -1, Msg: err.Error()})
			continue
		}
		log.Runs = append(log.Runs, l.Runs...)
	}
	return log, warns, nil
}

// Expand resolves patterns to a sorted, de-duplicated file list.
func Expand(patterns []string) ([]string, error) {
	seen := map[string]bool{}
	var files []string
	for _, p := range patterns {
		matches, err := filepath.Glob(p)
		if err != nil {
			return nil, fmt.Errorf("bad pattern %q: %w", p, err)
		}
		for _, m := range matches {
			if fi, err := os.Stat(m); err != nil || fi.IsDir() {
				continue
			}
			if !seen[m] {
				seen[m] = true
				files = append(files, m)
			}
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: %v", ErrNoFiles, patterns)
	}
	sort.Strings(files)
	return files, nil
}

// LoadFile reads one SARIF file. A file that cannot be read or is not a SARIF
// log returns an error; invalid runs inside a valid log become warnings.
func LoadFile(path string, opts Options) (*Log, []Warning, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file
	return Read(f, path, opts)
}

// Read parses a SARIF log from r. source names the input in warnings.
func Read(r io.Reader, source string, opts Options) (*Log, []Warning, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	return Parse(data, source, opts)
}

// Parse parses SARIF bytes. See LoadFile for the error contract.
func Parse(data []byte, source string, opts Options) (*Log, []Warning, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, nil, fmt.Errorf("not a SARIF log: %w", err)
	}
	if env.Version != Version {
		return nil, nil, fmt.Errorf("unsupported SARIF version %q (want %s)", env.Version, Version)
	}
	log := &Log{}
	var warns []Warning
	for i, raw := range env.Runs {
		run, err := parseRun(raw, opts)
		if err != nil {
			warns = append(warns, Warning{Source: source, Run: i, Msg: "skipped: " + err.Error()})
			continue
		}
		log.Runs = append(log.Runs, &SourcedRun{Run: run, Source: source, Index: i, raw: raw})
	}
	return log, warns, nil
}

// parseRun decodes and validates a single run.
func parseRun(raw json.RawMessage, opts Options) (*Run, error) {
	if !opts.SkipValidation {
		if err := validateRun(raw); err != nil {
			return nil, err
		}
	}
	var run Run
	if err := json.Unmarshal(raw, &run); err != nil {
		return nil, fmt.Errorf("decode run: %w", err)
	}
	if DriverName(&run) == "" {
		return nil, errors.New("run has no tool.driver.name")
	}
	return &run, nil
}

// marshal encodes v compactly without HTML escaping.
func marshal(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Write encodes the log as one SARIF document holding every run, in order,
// each as its original JSON plus sarifix's patches.
func (l *Log) Write(w io.Writer) error {
	runs := make([]json.RawMessage, 0, len(l.Runs))
	for _, r := range l.Runs {
		raw, err := r.JSON()
		if err != nil {
			return err
		}
		runs = append(runs, raw)
	}
	doc, err := marshal(struct {
		Schema  string            `json:"$schema"`
		Version string            `json:"version"`
		Runs    []json.RawMessage `json:"runs"`
	}{SchemaURI, Version, runs})
	if err != nil {
		return err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, doc, "", "  "); err != nil {
		return err
	}
	out.WriteByte('\n')
	_, err = w.Write(out.Bytes())
	return err
}

// WriteFile writes the log to path, creating parent directories.
func (l *Log) WriteFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := l.Write(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
