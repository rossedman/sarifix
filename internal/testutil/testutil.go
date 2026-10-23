// Package testutil builds large synthetic SARIF inputs for benchmarks.
package testutil

import (
	"bytes"
	"fmt"
)

// LargeSARIF returns a valid SARIF 2.1.0 log of roughly size bytes with
// results spread across files and rules, like a big Trivy or Checkov run.
func LargeSARIF(size int) []byte {
	var b bytes.Buffer
	b.Grow(size + 4096)
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"bench","rules":[`)
	for r := 0; r < 50; r++ {
		if r > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"R%03d","shortDescription":{"text":"Rule %d"},"help":{"text":"Fix rule %d by doing the right thing."}}`, r, r, r)
	}
	b.WriteString(`]}},"results":[`)
	for i := 0; b.Len() < size; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"ruleId":"R%03d","level":"warning","message":{"text":"Finding %d: resource does not follow the policy for this rule"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"modules/m%d/main.tf"},"region":{"startLine":%d,"endLine":%d,`+
			`"snippet":{"text":"resource \"aws_s3_bucket\" \"b%d\" {\n  bucket = \"name-%d\"\n}\n"}}}}]}`,
			i%50, i, i%400, i%300+1, i%300+3, i, i)
	}
	b.WriteString(`]}]}`)
	return b.Bytes()
}
