package sarif

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/xeipuuv/gojsonschema"
)

// schemaJSON is the official OASIS SARIF 2.1.0 schema (errata01).
//
//go:embed sarif-schema-2.1.0.json
var schemaJSON []byte

var (
	schemaOnce sync.Once
	schema     *gojsonschema.Schema
	schemaErr  error
)

// maxSchemaErrors caps how many schema errors are reported for one run.
const maxSchemaErrors = 3

// compiledSchema compiles the embedded schema once.
func compiledSchema() (*gojsonschema.Schema, error) {
	schemaOnce.Do(func() {
		schema, schemaErr = gojsonschema.NewSchema(gojsonschema.NewBytesLoader(schemaJSON))
	})
	return schema, schemaErr
}

// validateRun checks one raw run against the schema by wrapping it in a
// minimal log, so one bad run doesn't invalidate the others in its file.
func validateRun(raw json.RawMessage) error {
	doc, err := json.Marshal(struct {
		Version string            `json:"version"`
		Runs    []json.RawMessage `json:"runs"`
	}{Version, []json.RawMessage{raw}})
	if err != nil {
		return err
	}
	return validateDoc(doc)
}

// Validate checks a whole SARIF document against the 2.1.0 schema.
func Validate(doc []byte) error {
	return validateDoc(doc)
}

// validateDoc runs the schema over doc and summarizes the first errors.
func validateDoc(doc []byte) error {
	s, err := compiledSchema()
	if err != nil {
		return fmt.Errorf("compile SARIF schema: %w", err)
	}
	res, err := s.Validate(gojsonschema.NewBytesLoader(doc))
	if err != nil {
		return fmt.Errorf("schema validation: %w", err)
	}
	if res.Valid() {
		return nil
	}
	errs := res.Errors()
	msgs := make([]string, 0, maxSchemaErrors)
	for i, e := range errs {
		if i == maxSchemaErrors {
			msgs = append(msgs, fmt.Sprintf("and %d more", len(errs)-maxSchemaErrors))
			break
		}
		msgs = append(msgs, e.String())
	}
	return errors.New("invalid SARIF: " + strings.Join(msgs, "; "))
}
