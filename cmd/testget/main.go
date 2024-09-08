package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/ksinica/spoof"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stdout, "Usage:")
		fmt.Fprintln(os.Stdout, "\t", os.Args[0], "<url>")
		os.Exit(1)
	}

	c := http.Client{
		Transport: &spoof.Transport{},
	}

	req, err := http.NewRequest(http.MethodGet, os.Args[1], nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	res, err := c.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	defer res.Body.Close()

	if _, err := io.Copy(os.Stdout, res.Body); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	os.Exit(0)
}
