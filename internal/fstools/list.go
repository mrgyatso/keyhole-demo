package fstools

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func (c *call) listDir(a proto.ListDirArgs) (proto.ListDirResult, error) {
	t, err := c.open(a.Path)
	if err != nil {
		return proto.ListDirResult{}, err
	}
	defer t.close()
	if !t.info.IsDir() {
		return proto.ListDirResult{}, failf(proto.ErrNotRegular, "%s is a file, not a directory; use stat or read_file", a.Path)
	}
	entries, err := readDirSorted(t.file)
	if err != nil {
		return proto.ListDirResult{}, failf(proto.ErrIO, "reading %s: %v", a.Path, err)
	}
	limit := clampLimit(a.Limit, c.caps.maxList)
	res := proto.ListDirResult{Path: t.path, Entries: []proto.FileInfo{}}
	rules := c.allowRules()
	for i, e := range entries {
		if i%256 == 0 {
			if err := c.ctx.Err(); err != nil {
				return proto.ListDirResult{}, err
			}
		}
		info, err := e.Info()
		if err != nil {
			continue // removed since the directory was read
		}
		child := filepath.Join(t.path, e.Name())
		if !policy.Decide(c.goos, rules, child, info.IsDir() && !isLink(info)).Allowed {
			res.Omitted++
			continue
		}
		if len(res.Entries) == limit {
			res.Truncated = true
			continue
		}
		res.Entries = append(res.Entries, fileInfo(child, info))
	}
	return res, nil
}

// readDirSorted reads every entry of an open directory, sorted by name.
// Entry types come from the directory itself: links are never followed.
func readDirSorted(f *os.File) ([]fs.DirEntry, error) {
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}
