package spoof

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
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

// Transport implements http.RoundTripper with the ability to be
// fingerprinted as a Chrome browser. It tries to evade TLS fingerprinting
// and sends common browser headers.
//
// The transport does not overwrite user-specified headers, so the user
// is able to specify, for example, a custom "Accept-Language" header.
// Use with care, as this might thwart evasion efforts.
//
// When setting the "Accept-Encoding" header, the user is responsible for
// decoding the request body.
//
// There's no idle connection pool implemented yet, so the connections
// are closed after serving a request.
type Transport struct {
	RootCAs            *x509.CertPool
	InsecureSkipVerify bool

	once sync.Once
	h2   http2.Transport
}

func (tr *Transport) init() {
	tr.h2.MaxHeaderListSize = 262144
}

func withDeadline[T net.Conn](ctx context.Context, conn T, f func(T) error) error {
	dl, ok := ctx.Deadline()
	if ok {
		if err := conn.SetDeadline(dl); err != nil {
			return err
		}
	}

	if err := f(conn); err != nil {
		return err
	}

	return conn.SetDeadline(time.Time{})
}

func (tr *Transport) dialTLSContext(ctx context.Context, network, addr string) (*utls.UConn, string, error) {
	conn, err := new(net.Dialer).DialContext(ctx, network, addr)
	if err != nil {
		return nil, "", err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}

	utlsConn := utls.UClient(
		conn,
		&utls.Config{
			RootCAs:            tr.RootCAs,
			ServerName:         host,
			InsecureSkipVerify: tr.InsecureSkipVerify,
		},
		utls.HelloChrome_120,
	)

	if err := withDeadline(ctx, utlsConn, func(conn *utls.UConn) error {
		return conn.Handshake()
	}); err != nil {
		return nil, "", errors.Join(err, utlsConn.Close())
	}

	return utlsConn, utlsConn.ConnectionState().NegotiatedProtocol, nil
}

func (tr *Transport) decodeContent(res *http.Response) error {
	var (
		encodings = strings.Split(res.Header.Get("Content-Encoding"), ",")
		body      = res.Body
	)

	for _, encoding := range slices.Backward(encodings) {
		switch encoding {
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
			return fmt.Errorf("spoof: unsupported content encoding %q", encoding)
		}
	}

	res.Header.Del("Content-Encoding")
	res.Body = body

	return nil
}

func (tr *Transport) roundTrip1(conn net.Conn, req *http.Request) (res *http.Response, err error) {
	err = withDeadline(req.Context(), conn, func(conn net.Conn) error {
		if err := req.Write(conn); err != nil {
			return err
		}

		res, err = http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return errors.Join(err, conn.Close())
		}

		return nil
	})
	return
}

func (tr *Transport) roundTrip2(conn net.Conn, req *http.Request) (res *http.Response, err error) {
	err = withDeadline(req.Context(), conn, func(conn net.Conn) error {
		h2Conn, err := tr.h2.NewClientConn(conn)
		if err != nil {
			return err
		}

		res, err = h2Conn.RoundTrip(req)
		if err != nil {
			return errors.Join(err, h2Conn.Close())
		}

		return nil
	})
	return res, nil
}

func addrFromURL(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}

	if u.Scheme == "https" {
		return u.Host + ":443"
	}

	return u.Host + ":80"
}

func applyHeaders(h http.Header) {
	for k, v := range chromeHeaders {
		if _, ok := h[k]; !ok {
			h.Set(k, v)
		}
	}
}

func (tr *Transport) roundTrip(req *http.Request) (*http.Response, error) {
	var (
		addr        = addrFromURL(req.URL)
		conn        net.Conn
		proto       string
		err         error
		_, noDecode = req.Header["Accept-Encoding"]
		res         *http.Response
	)

	switch req.URL.Scheme {
	case "http":
		conn, err = new(net.Dialer).DialContext(req.Context(), "tcp", addr)
	case "https":
		conn, proto, err = tr.dialTLSContext(req.Context(), "tcp", addr)
	default:
		err = fmt.Errorf("spoof: unsupported scheme %q", req.URL.Scheme)
	}
	if err != nil {
		return nil, err
	}

	applyHeaders(req.Header)

	switch proto {
	case "http/1.1", "":
		res, err = tr.roundTrip1(conn, req)
	case "h2":
		res, err = tr.roundTrip2(conn, req)
	default:
		err = fmt.Errorf("spoof: unsupported protocol %q", proto)
	}
	if err != nil {
		return nil, err
	}

	res.Body = newReaderCloser(res.Body, newMultiCloser(res.Body, conn))

	if !noDecode {
		if err := tr.decodeContent(res); err != nil {
			return nil, errors.Join(err, drainAndClose(res.Body))
		}
	}

	return res, nil
}

func (tr *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.once.Do(tr.init)
	return tr.roundTrip(req)
}
