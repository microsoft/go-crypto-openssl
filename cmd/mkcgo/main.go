package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"strings"

	"github.com/golang-fips/openssl/v2/internal/mkcgo"
)

var (
	fileName      = flag.String("out", "", "output file name (standard output if omitted)")
	includeHeader = flag.String("include", "", "include header file")
	packageName   = flag.String("package", "", "package name")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: mkcgo [flags] [path ...]\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(1)
}

func main() {
	// Set up and parse flags.
	flag.Usage = usage
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "no files to parse provided")
		usage()
	}

	// Parse source files.
	src, err := mkcgo.Parse(flag.Args()...)
	if err != nil {
		log.Fatal(err)
	}

	var gobuf, go124buf, cbuf bytes.Buffer
	generateGo(src, &gobuf)
	generateGo124(src, &go124buf)
	generateC(src, &cbuf)

	// Format the generated Go source code.
	godata := goformat(gobuf.Bytes())
	go124data := goformat(go124buf.Bytes())

	var baseName string
	if *fileName == "" {
		baseName = "mkcgo"
	} else {
		baseName = strings.TrimSuffix(*fileName, ".go")
	}

	for _, d := range []struct {
		name string
		data []byte
	}{
		{baseName + ".go", godata},
		{baseName + "_go124.go", go124data},
		{baseName + ".c", cbuf.Bytes()},
	} {
		var err error
		if *fileName == "" {
			// Write output. If no explicit output file is specified,
			// // write both Go and C output to stdout.
			os.Stdout.WriteString("// === " + d.name + " ===\n\n")
			_, err = os.Stdout.Write(d.data)
		} else {
			err = os.WriteFile(d.name, d.data, 0o644)
		}
		if err != nil {
			log.Fatal(err)
		}
	}
}

func writeTempSourceFile(data []byte) (string, error) {
	f, err := os.CreateTemp("", "mkcgo-generated-*.go")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name()) // best effort
		return "", err
	}
	return f.Name(), nil
}

func goformat(data []byte) []byte {
	data, err := format.Source(data)
	if err != nil {
		log.Printf("failed to format source: %v", err)
		f, err := writeTempSourceFile(data)
		if err != nil {
			log.Fatalf("failed to write unformatted source to file: %v", err)
		}
		log.Fatalf("for diagnosis, wrote unformatted source to %v", f)
	}
	return data
}
