// Package main is a fixture with a seeded errcheck finding.
package main

import "os"

func main() {
	f, _ := os.Create("out.txt")
	f.Close()
}
