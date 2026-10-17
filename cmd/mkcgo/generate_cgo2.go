// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"go/parser"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/microsoft/go-crypto-openssl/internal/mkcgo"
)

// generateGoCgo2 generates Go-syntax bindings for the cgo2 prototype ending at
// https://go-review.googlesource.com/c/go/+/838206/1. The Go toolchain generates
// the ABI trampolines; neither a C compiler nor mkcgo's syscallN is needed.
func generateGoCgo2(src *mkcgo.Source, w, bindings io.Writer) error {
	if err := validateCgo2(src); err != nil {
		return err
	}
	// These are the platforms supported by the prototype. In particular, the
	// type mappings below assume the LP64 ABI, not Windows' LLP64 ABI.
	tags := "goexperiment.cgo2 && cgo && (linux || darwin) && (amd64 || arm64)"
	if *extratags != "" {
		tags += " && (" + *extratags + ")"
	}
	for _, out := range []io.Writer{w, bindings} {
		printHeader(out)
		fmt.Fprintf(out, "//go:build %s\n\n", tags)
		fmt.Fprintf(out, "package %s\n\n", *packageName)
	}

	// Keep the binding declarations separate from the wrappers and loader state.
	fmt.Fprintln(bindings, "/*")
	for _, fn := range src.Funcs {
		if !fnCalledFromGo(fn) {
			continue
		}
		// The prototype names function-pointer calls fp_<receiver type>.
		// Direct bindings use the Go declaration's name without its leading _.
		name := strings.TrimPrefix(fnCName(fn), "_")
		if dynload() {
			name = "fp_" + cgo2FuncType(fn)
		}
		if fn.NoEscape {
			fmt.Fprintf(bindings, "#cgo noescape %s\n", name)
		}
		if fn.NoCallback {
			fmt.Fprintf(bindings, "#cgo nocallback %s\n", name)
		}
	}
	if dynload() {
		fmt.Fprintf(bindings, "#cgo noescape %s\n", strings.TrimPrefix(cgo2LookupName(), "_"))
		fmt.Fprintf(bindings, "#cgo nocallback %s\n", strings.TrimPrefix(cgo2LookupName(), "_"))
	}
	fmt.Fprintln(bindings, "*/")
	fmt.Fprintln(bindings, "import \"C\"")
	fmt.Fprintln(bindings, "import \"unsafe\"")
	fmt.Fprintln(bindings)
	if len(src.Externs) != 0 {
		fmt.Fprintln(w, "import \"C\"")
	}
	fmt.Fprintln(w, "import \"unsafe\"")
	for _, fn := range src.Funcs {
		if fnCalledFromGo(fn) && fnNeedErrWrapper(fn) {
			fmt.Fprintln(w, "import \"runtime\"")
			break
		}
	}
	fmt.Fprintln(w, "\nvar _ unsafe.Pointer")
	fmt.Fprintln(w)

	for _, def := range src.TypeDefs {
		fmt.Fprintf(bindings, "//cgo:binding C.%s\n", def.Name)
		typ := cgo2GoType(def.Type)
		if typ == "unsafe.Pointer" {
			fmt.Fprintf(bindings, "type %s unsafe.Pointer\n\n", goSymName(def.Name))
		} else {
			fmt.Fprintf(bindings, "type %s = %s\n\n", goSymName(def.Name), typ)
		}
	}
	for _, enum := range src.Enums {
		if enum.Type != "" {
			fmt.Fprintf(bindings, "//cgo:binding C.%s\n", enum.Type)
			fmt.Fprintf(bindings, "type %s int32\n\n", goSymName(enum.Type))
		}
		for _, value := range enum.Values {
			fmt.Fprintf(bindings, "//cgo:binding C.%s\n", value.Name)
			if enum.Type != "" {
				fmt.Fprintf(bindings, "const %s %s = %s\n\n", goSymName(value.Name), goSymName(enum.Type), value.Value)
			} else {
				fmt.Fprintf(bindings, "const %s = %s\n\n", goSymName(value.Name), value.Value)
			}
		}
	}
	for _, ext := range src.Externs {
		cgo2Binding(bindings, ext.Name, ext.Framework)
		fmt.Fprintf(bindings, "var _mkcgo_var_%s %s\n\n", ext.Name, cgo2GoType(ext.Type))
		// Like the other backends, expose the initial value of the C variable.
		// C selectors are rewritten by cgo; plain Go variable references aren't.
		fmt.Fprintf(w, "var %s = C.%s\n\n", goSymName(ext.Name), ext.Name)
	}

	if dynload() {
		cgo2Binding(bindings, "dlsym", mkcgo.Framework{})
		fmt.Fprintf(bindings, "func %s(handle unsafe.Pointer, name *byte) unsafe.Pointer\n\n", cgo2LookupName())
		generateCgo2Loaders(src, w)
	}
	for _, fn := range src.Funcs {
		if !fnCalledFromGo(fn) {
			continue
		}
		if dynload() {
			fmt.Fprintf(bindings, "type %s uintptr\n\n", cgo2FuncType(fn))
		}
		if fn.VariadicTarget != "" {
			fmt.Fprintf(bindings, "//cgo:variadic %d\n", cgo2FixedParams(src, fn))
		}
		if dynload() {
			fmt.Fprintf(bindings, "//cgo:funcptr\nfunc (fp %s) Call(", cgo2FuncType(fn))
		} else {
			cgo2Binding(bindings, fn.ImportName(), fn.Framework)
			fmt.Fprintf(bindings, "func %s(", fnCName(fn))
		}
		fmt.Fprint(bindings, join(fn.Params, func(i int, p *mkcgo.Param) string {
			if isVoid(p.Type) {
				return ""
			}
			return fmt.Sprintf("p%d %s", i, cgo2GoType(p.Type))
		}, ", "))
		fmt.Fprintf(bindings, ") %s\n\n", cgo2GoType(fn.Ret))
		if fn.Optional {
			fmt.Fprintf(w, "func %s() bool { return _mkcgo_%s != 0 }\n\n", fnGoNameAvailable(fn), fn.ImportName())
		}
		generateCgo2Fn(src, fn, w)
	}
	return nil
}

func cgo2Binding(w io.Writer, name string, framework mkcgo.Framework) {
	fmt.Fprintf(w, "//cgo:binding C.%s", name)
	if path := getFrameworkPath(framework); path != "" {
		fmt.Fprintf(w, " %q", path)
	}
	fmt.Fprintln(w)
}

func cgo2FuncType(fn *mkcgo.Func) string {
	return "_mkcgo_func_" + fn.Name
}

func cgo2LookupName() string {
	base := strings.TrimSuffix(filepath.Base(autogeneratedFileName(".go")), ".go")
	base = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, base)
	return "_mkcgo_dlsym_" + base
}

// cgo2GoType uses Go types directly, including floating-point types that the
// syscallN backend cannot pass. The generated build constraints guarantee LP64.
func cgo2GoType(typ string) string {
	typ = strings.TrimPrefix(typ, "const ")
	switch typ {
	case "float":
		return "float32"
	case "double":
		return "float64"
	}
	if strings.HasSuffix(typ, "*") && !strings.HasPrefix(typ, "void*") {
		return "*" + cgo2GoType(strings.TrimSuffix(typ, "*"))
	}
	goType, _ := cTypeToGo(typ, false)
	return goType
}

func cgo2UnderlyingType(src *mkcgo.Source, typ string) string {
	for {
		typ = strings.TrimPrefix(typ, "const ")
		found := false
		for _, def := range src.TypeDefs {
			if def.Name == typ {
				typ = def.Type
				found = true
				break
			}
		}
		if !found {
			return typ
		}
	}
}

func cgo2FixedParams(src *mkcgo.Source, fn *mkcgo.Func) int {
	for _, target := range src.Funcs {
		if target.Name == fn.VariadicTarget {
			return len(target.Params) - 1
		}
	}
	return 0
}

func cgo2ErrorCondition(src *mkcgo.Source, fn *mkcgo.Func) string {
	typ := cgo2UnderlyingType(src, fn.Ret)
	cond := strings.ReplaceAll(fn.ErrCond, "NULL", "nil")
	if cond == "" {
		switch {
		case strings.HasSuffix(typ, "*"):
			cond = "== nil"
		case typ == "bool":
			cond = "== false"
		default:
			cond = "<= 0"
		}
	}
	return "_ret " + cond
}

func validateCgo2(src *mkcgo.Source) error {
	if *nocgo {
		return fmt.Errorf("-cgo2 and -nocgo are mutually exclusive")
	}
	if !dynamic() && !dynload() {
		return fmt.Errorf("unsupported cgo2 mode %q", *mode)
	}
	if *includeHeader != "" {
		return fmt.Errorf("-cgo2 does not support -include; declare the types in the input header")
	}
	types := make(map[string]string)
	for _, def := range src.TypeDefs {
		types[def.Name] = def.Type
	}
	for _, enum := range src.Enums {
		if enum.Type != "" {
			types[enum.Type] = "int"
		}
	}
	var checkType func(string, map[string]bool) error
	checkType = func(typ string, seen map[string]bool) error {
		typ = strings.TrimRight(strings.TrimPrefix(typ, "const "), "*")
		if isStdType(typ) || typ == "float" || typ == "double" || typ == "..." {
			return nil
		}
		if seen[typ] {
			return fmt.Errorf("cyclic cgo2 typedef %q", typ)
		}
		underlying, ok := types[typ]
		if !ok {
			return fmt.Errorf("unsupported cgo2 type %q", typ)
		}
		seen[typ] = true
		return checkType(underlying, seen)
	}
	check := func(typ string) error { return checkType(typ, make(map[string]bool)) }
	for _, def := range src.TypeDefs {
		if err := check(def.Name); err != nil {
			return err
		}
	}
	for _, ext := range src.Externs {
		if ext.Static {
			return fmt.Errorf("cgo2 does not support static extern %s", ext.Name)
		}
		if err := check(ext.Type); err != nil {
			return fmt.Errorf("%s: %w", ext.Name, err)
		}
	}
	for _, fn := range src.Funcs {
		if fn.Static {
			return fmt.Errorf("cgo2 does not support static function %s", fn.Name)
		}
		if fn.Optional && !dynload() {
			return fmt.Errorf("%s: optional functions require -mode dynload with -cgo2", fn.Name)
		}
		if err := check(fn.Ret); err != nil {
			return fmt.Errorf("%s: %w", fn.Name, err)
		}
		for _, p := range fn.Params {
			if err := check(p.Type); err != nil {
				return fmt.Errorf("%s: %w", fn.Name, err)
			}
		}
		if fn.VariadicTarget != "" && len(fn.Params) < cgo2FixedParams(src, fn) {
			return fmt.Errorf("%s: fewer parameters than variadic target %s", fn.Name, fn.VariadicTarget)
		}
		if fnNeedErrWrapper(fn) {
			if _, err := parser.ParseExpr(cgo2ErrorCondition(src, fn)); err != nil {
				return fmt.Errorf("%s: unsupported cgo2 error condition: %w", fn.Name, err)
			}
		}
	}
	return nil
}

func generateCgo2Loaders(src *mkcgo.Source, w io.Writer) {
	// Library handles belong to the caller. runtime/cgo.Library cannot adopt
	// an existing handle, so bind dlsym and call the resolved function pointers.
	for _, fn := range src.Funcs {
		if fn.VariadicTarget == "" {
			typ := "uintptr"
			if fnCalledFromGo(fn) {
				typ = cgo2FuncType(fn)
			}
			// Variadic targets have no single fixed-signature Call binding,
			// so keep their symbol addresses as uintptr.
			fmt.Fprintf(w, "var _mkcgo_%s %s\n", fn.Name, typ)
		}
	}
	fmt.Fprintln(w)
	for _, tag := range src.Tags() {
		var funcs []*mkcgo.Func
		var names []string
		for _, fn := range src.Funcs {
			if fn.VariadicTarget != "" {
				continue
			}
			tags := fn.Tags
			if len(tags) == 0 {
				tags = []mkcgo.TagAttr{{}}
			}
			for _, attr := range tags {
				if attr.Tag == tag {
					name := attr.Name
					if name == "" {
						name = fn.Name
					}
					funcs = append(funcs, fn)
					names = append(names, name)
					break
				}
			}
		}
		fmt.Fprintf(w, "func %s_%s(handle unsafe.Pointer) {\n", goSymName("mkcgoLoad"), tag)
		for i, fn := range funcs {
			value := fmt.Sprintf("uintptr(%s(handle, unsafe.StringData(%q)))", cgo2LookupName(), names[i]+"\x00")
			if fnCalledFromGo(fn) {
				value = cgo2FuncType(fn) + "(" + value + ")"
			}
			fmt.Fprintf(w, "\t_mkcgo_%s = %s\n", fn.Name, value)
			if !fn.Optional {
				fmt.Fprintf(w, "\tif _mkcgo_%s == 0 { panic(%q) }\n", fn.Name, "cannot get required symbol "+names[i])
			}
		}
		fmt.Fprintf(w, "}\n\n")
		fmt.Fprintf(w, "func %s_%s() {\n", goSymName("mkcgoUnload"), tag)
		for _, fn := range funcs {
			fmt.Fprintf(w, "\t_mkcgo_%s = 0\n", fn.Name)
		}
		fmt.Fprintf(w, "}\n\n")
	}
}

func generateCgo2Fn(src *mkcgo.Source, fn *mkcgo.Func, w io.Writer) {
	paramName := func(i int, p *mkcgo.Param) string {
		if p.Name != "" {
			return p.Name
		}
		return "_arg" + strconv.Itoa(i)
	}
	params := join(fn.Params, func(i int, p *mkcgo.Param) string {
		if isVoid(p.Type) || shouldSkipSliceLenParam(fn, p) {
			return ""
		}
		typ := cgo2GoType(p.Type)
		if _, ok := fn.SliceFromPtr(p.Name); ok {
			typ = cgo2GoType(cgo2UnderlyingType(src, p.Type))
			if typ == "unsafe.Pointer" {
				typ = "*byte"
			}
			typ = "[]" + strings.TrimPrefix(typ, "*")
		}
		return paramName(i, p) + " " + typ
	}, ", ")
	args := join(fn.Params, func(i int, p *mkcgo.Param) string {
		if isVoid(p.Type) {
			return ""
		}
		if slice, ok := fn.SliceFromLen(p.Name); ok && !isPointerParam(p) {
			length := "len(" + slice.Ptr + ")"
			if typ := cgo2GoType(p.Type); typ != "int" {
				length = typ + "(" + length + ")"
			}
			return length
		}
		if _, ok := fn.SliceFromPtr(p.Name); ok {
			data := "unsafe.SliceData(" + paramName(i, p) + ")"
			if cgo2GoType(cgo2UnderlyingType(src, p.Type)) == "unsafe.Pointer" {
				data = "unsafe.Pointer(" + data + ")"
				if typ := cgo2GoType(p.Type); typ != "unsafe.Pointer" {
					data = typ + "(" + data + ")"
				}
			}
			return data
		}
		return paramName(i, p)
	}, ", ")
	call := fnCName(fn)
	if dynload() {
		if fn.VariadicTarget != "" {
			call = fmt.Sprintf("%s(_mkcgo_%s)", cgo2FuncType(fn), fn.ImportName())
		}
		call += ".Call"
	}
	call += "(" + args + ")"
	fmt.Fprintf(w, "func %s(%s)", goSymName(fn.Name), params)
	ret := cgo2GoType(fn.Ret)
	if fnNeedErrWrapper(fn) {
		fmt.Fprintf(w, " (%s, error)", ret)
	} else if ret != "" {
		fmt.Fprintf(w, " %s", ret)
	}
	fmt.Fprintln(w, " {")
	generateSliceLenPointerChecks(fn, w)
	if fnNeedErrWrapper(fn) {
		fmt.Fprintln(w, "\t// Keep the call and retrieval of its thread-local error state on the same OS thread.")
		fmt.Fprintln(w, "\truntime.LockOSThread()")
		fmt.Fprintln(w, "\tdefer runtime.UnlockOSThread()")
		fmt.Fprintf(w, "\t_ret := %s\n", call)
		fmt.Fprintln(w, "\tvar _err uintptr")
		fmt.Fprintf(w, "\tif %s { _err = retrieveErrorState() }\n", cgo2ErrorCondition(src, fn))
		fmt.Fprintf(w, "\treturn _ret, newMkcgoErr(%q, _err)\n", fn.Name)
	} else if ret != "" {
		fmt.Fprintf(w, "\treturn %s\n", call)
	} else {
		fmt.Fprintf(w, "\t%s\n", call)
	}
	fmt.Fprintf(w, "}\n\n")
}
