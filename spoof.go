package spoof

import (
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var chromeHeaders = map[string]string{
	`sec-ch-ua`:                 `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`,
	`sec-ch-ua-mobile`:          `?0`,
	`sec-ch-ua-platform`:        `"macOS"`,
	`upgrade-insecure-requests`: `1`,
	`User-Agent`:                `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36`,
	`Accept`:                    `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`,
	`sec-fetch-site`:            `cross-site`,
	`sec-fetch-mode`:            `navigate`,
	`sec-fetch-user`:            `?1`,
	`sec-fetch-dest`:            `document`,
	`Accept-Encoding`:           `gzip, deflate, br, zstd`,
	`Accept-Language`:           `en-GB,en-US,q=0.9,en;q=0.8`,
	`priority`:                  `u=0, i`,
}

func applyHeaders(h http.Header) {
	for k, v := range chromeHeaders {
		h.Set(k, v)
	}
}

type Transport struct {
	http2.Transport

	once sync.Once
}

func (t *Transport) init() {
	t.DialTLSContext = t.dialTLSContext
	t.MaxHeaderListSize = 262144
}

func copyConfig(c *tls.Config) *utls.Config {
	return &utls.Config{
		ServerName: c.ServerName,
	}
}

func (tr *Transport) dialTLSContext(ctx context.Context, network string, address string,
	config *tls.Config) (net.Conn, error) {
	conn, err := new(net.Dialer).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	tconn := utls.UClient(conn, copyConfig(config), utls.HelloChrome_120)

	dl, ok := ctx.Deadline()
	if ok {
		if err := tconn.SetDeadline(dl); err != nil {
			return nil, errors.Join(err, tconn.Close())
		}
	}
	if err := tconn.Handshake(); err != nil {
		return nil, errors.Join(err, tconn.Close())
	}

	if ok {
		if err := tconn.SetDeadline(time.Time{}); err != nil {
			return nil, errors.Join(err, tconn.Close())
		}
	}

	return tconn, nil
}

func (tr *Transport) decodeContent(res *http.Response) error {
	var (
		encodings = strings.Split(res.Header.Get("Content-Encoding"), ",")
		body      = res.Body
	)

	for i := len(encodings) - 1; i >= 0; i-- {
		switch encodings[i] {
		case "":
			continue

		case "gzip":
			rc, err := gzip.NewReader(body)
			if err != nil {
				return err
			}
			body = newReaderCloser(rc, newMultiCloser(rc, body))

		case "deflate":
			r := flate.NewReader(body)
			body = newReaderCloser(r, newMultiCloser(r, body))

		case "br":
			r := brotli.NewReader(body)
			body = newReaderCloser(r, body)

		case "zstd":
			d, err := zstd.NewReader(body)
			if err != nil {
				return err
			}
			body = newReaderCloser(d, newMultiCloser(newZstdCloser(d), body))

		default:
			return fmt.Errorf("unsupported content encoding: %s", encodings[i])
		}
	}

	res.Header.Del("Content-Encoding")
	res.Body = body

	return nil
}

func (tr *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.once.Do(tr.init)
	applyHeaders(req.Header)

	res, err := tr.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if err := tr.decodeContent(res); err != nil {
		return nil, errors.Join(err, drainAndClose(res.Body))
	}

	return res, nil
}
