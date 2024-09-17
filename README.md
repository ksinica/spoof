# spoof

[![GoDoc](https://godoc.org/github.com/ksinica/spoof?status.svg)](https://godoc.org/github.com/ksinica/spoof)

Spoof is a Go package that provides transport that enables HTTP client requests to look similar to Chrome browser. It tries to achieve this by evading TLS fingerprinting, changing HTTP/2 session parameters, and setting common browser headers.

> [!IMPORTANT]  
> This package is not able to bypass JavaScript-based browser checks or more sophisticated bot detectors.

> [!NOTE]  
> The package is alpha quality, breaking changes will be introduced.

## Usage
In order to use the transport, one needs to create a custom `http.Client` with it specified:

```go
	client := http.Client{
		Transport: spoof.Transport(),
	}

    // Create a request with desired parameters.

	res, err := client.Do(req)
	if err != nil {
        // ...
    }

    // ...
```

## License

Source code is available under the MIT [License](/LICENSE).
