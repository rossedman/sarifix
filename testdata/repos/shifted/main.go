// Package main is a fixture with a seeded errcheck finding.
package main

import "os"

// shifted moves the findings below down two lines.
var shifted = true

func main() {
	f, _ := os.Create("out.txt")
	f.Close()
	_ = shifted
}
