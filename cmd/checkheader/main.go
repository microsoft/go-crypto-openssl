package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
)

// The checking program implements all the checks at compile time, so there is no need to run it.
// The generation of the checking program follows these rules:
// - Lines are added in order of appearance.
// - Blank lines are discarded.
// - Comments are discarded unless they start with " #include", " #if" or " #endif".
// - Typedefs following this pattern "typedef void* GO_%name%_PTR" are translated into "#define %name% GO_%name%_PTR".
// - Function macros are validated against their definition in the OpenSSL headers. Example:
//   "DEFINEFUNC(int, RAND_bytes, (uint8_t *a0, size_t a1), (a0, a1))" => "__typeof__(int(*)(uint8_t *, size_t)) __check_0 = RAND_bytes;"

const description = `
Example: A check operation:
  go run ./cmd/checkheader --ossl_include /usr/local/src/openssl-1.1.1/include ./openssl/openssl_funcs.h 
Checkheader generates and runs a C program which verifies types and functions defined in the target
header file match the definitions in ossl_include.
`

var osslInclude = flag.String("ossl_include", "", "OpenSSL include directory. Required.")
var work = flag.Bool("work", false, "print the name of the temporary C program file and do not delete it when exiting.")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "\nUsage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\n", description)
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	if *osslInclude == "" {
		flag.Usage()
		os.Exit(1)
	}
	if _, err := os.Stat(*osslInclude); err != nil {
		log.Fatal(err)
	}
	s, err := generate(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	err = gccRun(s)
	if err != nil {
		log.Fatal(err)
	}
}

func gccRun(program string) error {
	f, err := os.CreateTemp("", "go-crypto-openssl-*.c")
	if err != nil {
		log.Fatal(err)
	}
	name := f.Name()
	if !*work {
		defer os.Remove(name)
	} else {
		defer log.Println(name)
	}
	if _, err = f.WriteString(program); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	p := exec.Command("gcc",
		"-c",                           // skip linking
		"-Werror",                      // promote all warnings to errors
		"-Wno-deprecated-declarations", // deprecation warnings are expected
		"-isystem", *osslInclude,       // OpenSSL include from --ossl_include must be prefered over system includes
		"-o", "/dev/null", // discard output
		name)
	p.Stderr = os.Stderr
	return p.Run()
}

func generate(header string) (string, error) {
	f, err := os.Open(header)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var b strings.Builder
	sc := bufio.NewScanner(f)
	var i int
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if checkDirective(&b, l) {
			continue
		}
		if checkTypedef(&b, l) {
			continue
		}
		if checkMacro(&b, l, i) {
			i++
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return b.String(), nil
}

func checkDirective(w io.Writer, l string) bool {
	if strings.HasPrefix(l, "// #include ") ||
		strings.HasPrefix(l, "// #if ") ||
		strings.HasPrefix(l, "// #endif") {
		fmt.Fprintln(w, l[len("// "):])
		return true
	}
	return false
}

func checkTypedef(w io.Writer, l string) bool {
	if !strings.HasPrefix(l, "typedef void* GO_") {
		return false
	}
	// Replace custom opaque pointer typedef with the proper OpenSSL type
	// so gcc does not complain about pointer mismatch.
	i1 := strings.Index(l, "GO_")
	i2 := strings.Index(l, "_PTR")
	if i2 < 0 {
		log.Println("unexpected line in typedef: " + l)
		return false
	}
	name := l[i1+3 : i2]
	fmt.Fprintf(w, "#define GO_%s_PTR %s*\n", name, name)
	return true
}

func checkMacro(w io.Writer, l string, i int) bool {
	if !strings.HasPrefix(l, "DEFINEFUNC") {
		return false
	}
	i1 := strings.IndexByte(l, '(')
	// The first ")," match is always the end of the argument list parameter.
	// We are not interested in the last parameter and parsing them would complicate the algorithm.
	// Matching against ')' is not enough as it when the argument list parameter contains function pointers.
	i2 := strings.Index(l, "),")
	if i1 < 0 || i2 < 0 {
		log.Println("unexpected line in function: " + l)
		return false
	}
	subs := l[i1+1 : i2+1]
	writeCheck := func(ret, name, args string) {
		fmt.Fprintf(w, "__typeof__(%s(*)%s) __check_%d = %s;\n", ret, args, i, name)
	}
	writeDefineFunc := func(cond string) {
		sp := strings.SplitN(subs, ",", 3)
		if cond != "" {
			fmt.Fprintf(w, "#if %s\n", cond)
		}
		writeCheck(sp[0], sp[1], sp[2])
		if cond != "" {
			fmt.Fprintln(w, "#endif")
		}
	}
	writeDefineFuncRename := func(cond string) {
		sp := strings.SplitN(subs, ",", 4)
		fmt.Fprintf(w, "#if %s\n", cond)
		writeCheck(sp[0], sp[2], sp[3])
		fmt.Fprintln(w, "#else")
		writeCheck(sp[0], sp[1], sp[3])
		fmt.Fprintln(w, "#endif")
	}
	switch l[:i1] {
	case "DEFINEFUNC":
		writeDefineFunc("")
	case "DEFINEFUNC_LEGACY_1_0":
		writeDefineFunc("OPENSSL_VERSION_NUMBER < 0x10100000L")
	case "DEFINEFUNC_LEGACY_1":
		writeDefineFunc("OPENSSL_VERSION_NUMBER < 0x30000000L")
	case "DEFINEFUNC_1_1":
		writeDefineFunc("OPENSSL_VERSION_NUMBER >= 0x10100000L")
	case "DEFINEFUNC_3_0":
		writeDefineFunc("OPENSSL_VERSION_NUMBER >= 0x30000000L")
	case "DEFINEFUNC_RENAMED_1_1":
		writeDefineFuncRename("OPENSSL_VERSION_NUMBER < 0x10100000L")
	case "DEFINEFUNC_RENAMED_3_0":
		writeDefineFuncRename("OPENSSL_VERSION_NUMBER < 0x30000000L")
	}
	return true
}
