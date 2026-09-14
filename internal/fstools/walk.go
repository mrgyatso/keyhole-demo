package fstools

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// errStop ends a walk early and quietly once a result cap is reached.
var errStop = errors.New("fstools: stop walk")

var errChanged = errors.New("fstools: entry changed since it was listed")

// visitFn sees one directory entry: its canonical path, its path relative
// to the walk's os.Root, what the directory listing says about it (links
// are not followed), and its depth (1 for the entries of the start
// directory). It returns whether to descend into it.
type visitFn func(path, rel string, info fs.FileInfo, depth int) (descend bool, err error)

// walk visits the tree below the open directory t in name order, down to
// maxDepth levels. It never follows links or reparse points, descends only
// where visit says so (visitors skip hard-denied subtrees), re-opens every
// subdirectory beneath the os.Root and checks its final path, and stops when
// the call's context ends or visit fails.
func (c *call) walk(t *target, maxDepth int, visit visitFn) error {
	entries, err := readDirSorted(t.file)
	if err != nil {
		return failf(proto.ErrIO, "reading %s: %v", t.path, err)
	}
	err = c.walkEntries(t, entries, t.path, t.rel, 1, maxDepth, visit)
	if errors.Is(err, errStop) {
		return nil
	}
	return err
}

func (c *call) walkEntries(t *target, entries []fs.DirEntry, dir, dirRel string, depth, maxDepth int, visit visitFn) error {
	for i, e := range entries {
		if i%64 == 0 {
			if err := c.ctx.Err(); err != nil {
				return err
			}
		}
		info, err := e.Info()
		if err != nil {
			continue // removed since the directory was read
		}
		p, rel := filepath.Join(dir, e.Name()), joinRel(dirRel, e.Name())
		descend, err := visit(p, rel, info, depth)
		if err != nil {
			return err
		}
		if !descend || depth >= maxDepth || !info.IsDir() || isLink(info) {
			continue
		}
		sub, _, err := c.openVerified(t, rel, p, true)
		if err != nil {
			continue
		}
		subEntries, err := readDirSorted(sub)
		sub.Close()
		if err != nil {
			continue
		}
		if err := c.walkEntries(t, subEntries, p, rel, depth+1, maxDepth, visit); err != nil {
			return err
		}
	}
	return nil
}

// openVerified opens an entry a walk found and checks that the handle is
// that same entry: the expected kind, not a reparse point, and at exactly
// the expected final path, so no link was followed, not even one swapped in
// after the listing was read.
func (c *call) openVerified(t *target, rel, want string, wantDir bool) (*os.File, fs.FileInfo, error) {
	f, err := t.root.OpenFile(rel, openFlags, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		var reparse bool
		if reparse, err = handleIsReparse(f); err == nil && (reparse || fi.IsDir() != wantDir || (!wantDir && !fi.Mode().IsRegular())) {
			err = errChanged
		}
	}
	if err == nil {
		var final string
		if final, err = finalPath(f); err == nil {
			if r, ok := policy.Rel(c.goos, want, final); !ok || r != "." {
				err = errChanged
			}
		}
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

func joinRel(dir, name string) string {
	if dir == "." {
		return name
	}
	return filepath.Join(dir, name)
}

// walkDepth applies a request's max_depth: 0 means the default, and no
// request goes deeper than MaxSearchDepth.
func walkDepth(d int) int {
	switch {
	case d <= 0:
		return proto.DefaultSearchDepth
	case d > proto.MaxSearchDepth:
		return proto.MaxSearchDepth
	}
	return d
}
