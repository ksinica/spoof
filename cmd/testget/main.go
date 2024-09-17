package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/ksinica/spoof"
)

func print(args ...any) {
	fmt.Fprintln(os.Stdout, args...)
}

func printError(args ...any) {
	fmt.Fprintln(os.Stderr, append([]any{"Error:"}, args...)...)
}

func main() {
	if len(os.Args) != 2 {
		print("Usage:")
		print("\t", os.Args[0], "<url>")
		os.Exit(1)
	}

	c := http.Client{
		Transport: spoof.Transport(),
	}

	req, err := http.NewRequest(http.MethodGet, os.Args[1], nil)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	res, err := c.Do(req)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	defer func() {
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	if _, err := io.Copy(os.Stdout, res.Body); err != nil {
		printError(err)
		os.Exit(1)
	}

	os.Exit(0)
}
