// Package cli wires sarifix's cobra commands, flags and viper settings.
//
// Each file in this package defines exactly one command and registers it in
// its own init(), so the command tree is built fresh for every Execute (and
// every test).
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"charm.land/fang/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/rossedman/sarifix/internal/ui"
	"github.com/rossedman/sarifix/internal/version"
	"github.com/rossedman/sarifix/pkg/config"
)

// Exit codes, part of the CLI contract.
const (
	ExitOK          = 0
	ExitRuntime     = 1
	ExitConfig      = 2
	ExitBatchFailed = 3
	// ExitFindings is check's code for "your changes introduced findings".
	// It shares 3 with ExitBatchFailed: both mean "the run worked, and
	// there is something to fix".
	ExitFindings = 3
)

// ExitError carries a specific exit code.
type ExitError struct {
	Code int
	Err  error
	// Silent means the command already reported the outcome itself, so
	// nothing more is printed (sarifix check --hook writes its own stderr).
	Silent bool
}

// Error returns the wrapped error's message.
func (e *ExitError) Error() string { return e.Err.Error() }

// Unwrap returns the wrapped error.
func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode maps an error from Execute to the process exit code.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	var ce *config.Errors
	if errors.As(err, &ce) {
		return ExitConfig
	}
	return ExitRuntime
}

// app is the state shared by every command in one invocation.
type app struct {
	v      *viper.Viper
	stdout io.Writer
	stderr io.Writer
	log    *slog.Logger
	styles ui.Styles
}

// registration adds a subcommand under parent (a space-separated path from
// the root; "" is the root itself).
type registration struct {
	parent string
	build  func(*app) *cobra.Command
}

// registry is filled by each command file's init().
var registry []registration

// register is called from init() in each command file.
func register(parent string, build func(*app) *cobra.Command) {
	registry = append(registry, registration{parent: parent, build: build})
}

// Execute builds the command tree and runs it with fang.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return ExecuteIO(ctx, args, os.Stdin, stdout, stderr)
}

// ExecuteIO is Execute with an explicit stdin, which sarifix check --hook
// reads the hook payload from.
func ExecuteIO(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	root := NewRoot(stdout, stderr)
	root.SetArgs(args)
	root.SetIn(stdin)
	info := version.Get()
	return fang.Execute(ctx, root,
		fang.WithVersion(info.Version),
		fang.WithCommit(info.Commit),
		fang.WithColorSchemeFunc(ui.ColorScheme),
		fang.WithErrorHandler(func(w io.Writer, styles fang.Styles, err error) {
			var ee *ExitError
			if errors.As(err, &ee) && ee.Silent {
				return
			}
			ui.ErrorHandler(w, styles, err)
		}),
		fang.WithNotifySignal(os.Interrupt),
	)
}

// NewRoot builds the full command tree writing to stdout and stderr.
func NewRoot(stdout, stderr io.Writer) *cobra.Command {
	a := &app{v: viper.New(), stdout: stdout, stderr: stderr, styles: ui.NewStyles(ui.IsDark())}
	root := &cobra.Command{
		Use:   "sarifix",
		Short: "Turn any SARIF scanner into a verified auto-fixer",
		Long: `sarifix reads SARIF findings from any scanner, has an AI agent fix them in
small single-rule batches, proves each fix by re-running the scanner and the
repo's tests, and publishes the result as a PR, review suggestions or local
edits.

Settings precedence: flag > SARIFIX_* environment variable > settings file
($XDG_CONFIG_HOME/sarifix/settings.yaml or ~/.sarifix/settings.yaml).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return a.init(cmd)
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	pf := root.PersistentFlags()
	pf.String("config", config.DefaultFile, "path to sarifix.yaml")
	pf.String("org-config", "", "org default config layered under --config")
	pf.String("repo", ".", "repository root")
	pf.Bool("json", false, "machine-readable JSON output")
	pf.String("log-level", "info", "log level: debug, info, warn, error")
	pf.String("settings", "", "settings file (default: search XDG config and home)")

	built := map[string]*cobra.Command{"": root}
	// Parents register before children because Go runs init() in file-name
	// order and parents sort first (config.go < config_validate.go); loop
	// until every registration is placed to be safe regardless.
	pending := append([]registration(nil), registry...)
	for len(pending) > 0 {
		var next []registration
		for _, r := range pending {
			parent, ok := built[r.parent]
			if !ok {
				next = append(next, r)
				continue
			}
			c := r.build(a)
			parent.AddCommand(c)
			path := strings.TrimSpace(r.parent + " " + c.Name())
			built[path] = c
		}
		if len(next) == len(pending) {
			panic(fmt.Sprintf("cli: unknown parent command %q", next[0].parent))
		}
		pending = next
	}
	return root
}

// init loads settings, binds flags and sets up logging.
func (a *app) init(cmd *cobra.Command) error {
	v := a.v
	v.SetEnvPrefix("SARIFIX")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	var bindErr error
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if err := v.BindPFlag(f.Name, f); err != nil && bindErr == nil {
			bindErr = err
		}
	})
	if bindErr != nil {
		return bindErr
	}
	if err := a.readSettings(); err != nil {
		return err
	}
	lg, err := ui.NewLogger(a.stderr, v.GetString("log-level"), v.GetBool("json"))
	if err != nil {
		return &ExitError{Code: ExitConfig, Err: err}
	}
	a.log = lg
	return nil
}

// readSettings loads the optional user settings file.
func (a *app) readSettings() error {
	v := a.v
	if f := v.GetString("settings"); f != "" {
		v.SetConfigFile(f)
	} else {
		v.SetConfigName("settings")
		v.SetConfigType("yaml")
		if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
			v.AddConfigPath(filepath.Join(x, "sarifix"))
		}
		if h, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(filepath.Join(h, ".config", "sarifix"))
			v.AddConfigPath(filepath.Join(h, ".sarifix"))
		}
	}
	if err := v.ReadInConfig(); err != nil {
		var nf viper.ConfigFileNotFoundError
		if errors.As(err, &nf) {
			return nil
		}
		return &ExitError{Code: ExitConfig, Err: fmt.Errorf("settings: %w", err)}
	}
	return nil
}

// repo returns the absolute repo root.
func (a *app) repo() (string, error) {
	return filepath.Abs(a.v.GetString("repo"))
}

// loadConfig loads and validates sarifix.yaml (plus the org layer). A
// relative --config is resolved against --repo.
func (a *app) loadConfig(opts config.ValidateOptions) (*config.Loaded, error) {
	repo, err := a.repo()
	if err != nil {
		return nil, err
	}
	path := a.v.GetString("config")
	if !filepath.IsAbs(path) {
		path = filepath.Join(repo, path)
	}
	l, err := config.LoadLayered(a.v.GetString("org-config"), path)
	if err != nil {
		return nil, err
	}
	if err := l.Validate(opts); err != nil {
		return nil, err
	}
	return l, nil
}

// jsonOut reports whether --json is set.
func (a *app) jsonOut() bool {
	return a.v.GetBool("json")
}

// writeJSON writes v as indented JSON to stdout.
func (a *app) writeJSON(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// out returns a color-aware writer for human output.
func (a *app) out() io.Writer {
	return ui.Writer(a.stdout)
}

// display shortens an absolute path to one relative to the working
// directory when it is inside it or at most two levels up, for human output.
func display(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(wd, p)
	if err != nil || strings.HasPrefix(rel, strings.Repeat(".."+string(filepath.Separator), 3)) || rel == filepath.Join("..", "..", "..") {
		return p
	}
	return rel
}
