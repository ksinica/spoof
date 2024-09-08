# spoof

[![GoDoc](https://godoc.org/github.com/ksinica/spoof?status.svg)](https://godoc.org/github.com/ksinica/spoof)

Spoof is a Go package that provides transport that enables HTTP client requests to look similar to Chrome browser. It tries to achieve this by evading TLS fingerprinting, changing HTTP/2 session parameters, and setting common browser headers.

The package is in alpha quality, will probably not work for more sophisticated bot detectors.

## License

Source code is available under the MIT [License](/LICENSE).