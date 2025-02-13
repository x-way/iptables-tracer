go-conntrack [![PkgGoDev](https://pkg.go.dev/badge/github.com/florianl/go-conntrack)](https://pkg.go.dev/github.com/florianl/go-conntrack) [![Go Report Card](https://goreportcard.com/badge/github.com/florianl/go-conntrack)](https://goreportcard.com/report/github.com/florianl/go-conntrack) [![Go](https://github.com/florianl/go-conntrack/actions/workflows/go.yml/badge.svg)](https://github.com/florianl/go-conntrack/actions/workflows/go.yml)
============

This is `go-conntrack` and it is written in [golang](https://golang.org/). It provides a [C](https://en.wikipedia.org/wiki/C_(programming_language))-binding free API to the conntrack subsystem of the [Linux kernel](https://www.kernel.org).

## Example

```golang
func main() {
	nfct, err := ct.Open(&ct.Config{})
	if err != nil {
		fmt.Println("could not create nfct:", err)
		return
	}
    defer nfct.Close()

    // Get all IPv4 entries of the expected table.
	sessions, err := nfct.Dump(ct.Expected, ct.IPv4)
	if err != nil {
		fmt.Println("could not dump sessions:", err)
		return
	}

    // Print out all expected sessions.
	for _, session := range sessions {
		fmt.Printf("%#v\n", session)
	}
}
```

## Requirements

* A version of Go that is [supported by upstream](https://golang.org/doc/devel/release.html#policy)
