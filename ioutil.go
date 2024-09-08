package spoof

import (
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
)

type multiCloser struct {
	closers []io.Closer
}

func (c *multiCloser) Close() (err error) {
	for _, c := range c.closers {
		err = errors.Join(err, c.Close())
	}
	return
}

func newMultiCloser(closers ...io.Closer) io.Closer {
	return &multiCloser{closers: closers}
}

type readerCloser struct {
	io.Reader
	io.Closer
}

func newReaderCloser(r io.Reader, c io.Closer) io.ReadCloser {
	return &readerCloser{Reader: r, Closer: c}
}

type zstdCloser struct {
	decoder *zstd.Decoder
}

func (c *zstdCloser) Close() error {
	c.decoder.Close()
	return nil
}

func newZstdCloser(decoder *zstd.Decoder) io.Closer {
	return &zstdCloser{decoder: decoder}
}

func drainAndClose(rc io.ReadCloser) error {
	_, err := io.Copy(io.Discard, rc)
	return errors.Join(err, rc.Close())
}
