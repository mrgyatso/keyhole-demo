package fstools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func (c *call) hashFile(a proto.HashFileArgs) (proto.HashFileResult, error) {
	t, err := c.open(a.Path)
	if err != nil {
		return proto.HashFileResult{}, err
	}
	defer t.close()
	if t.info.IsDir() {
		return proto.HashFileResult{}, failf(proto.ErrNotRegular, "%s is a directory", a.Path)
	}
	size := t.info.Size()
	if size > c.caps.maxFile {
		return proto.HashFileResult{}, failf(proto.ErrTooLarge, "%s is %d bytes; hash_file is limited to %d", a.Path, size, c.caps.maxFile)
	}
	h := sha256.New()
	n, err := io.Copy(h, ctxReader{c.ctx, io.NewSectionReader(t.file, 0, size)})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return proto.HashFileResult{}, err
		}
		return proto.HashFileResult{}, failf(proto.ErrIO, "reading %s: %v", a.Path, err)
	}
	return proto.HashFileResult{Path: t.path, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), ModTime: t.info.ModTime().UTC()}, nil
}

// ctxReader stops a long read when its context ends.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r ctxReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
