package fstools

import (
	"io/fs"
	"path/filepath"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func (c *call) stat(a proto.StatArgs) (proto.StatResult, error) {
	t, err := c.open(a.Path)
	if err != nil {
		return proto.StatResult{}, err
	}
	defer t.close()
	return proto.StatResult{FileInfo: fileInfo(t.path, t.info), Mode: t.info.Mode().String()}, nil
}

// fileInfo describes fi, found at the canonical path p. Links are reported
// as links, never followed.
func fileInfo(p string, fi fs.FileInfo) proto.FileInfo {
	info := proto.FileInfo{Name: filepath.Base(p), Path: p, ModTime: fi.ModTime().UTC()}
	switch {
	case isLink(fi):
		info.Type = proto.TypeSymlink
	case fi.IsDir():
		info.Type = proto.TypeDir
	case fi.Mode().IsRegular():
		info.Type, info.Size = proto.TypeFile, fi.Size()
	default:
		info.Type = proto.TypeOther
	}
	return info
}
