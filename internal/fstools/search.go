package fstools

import (
	"io/fs"
	"slices"
	"strings"

	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func (c *call) searchFiles(a proto.SearchFilesArgs) (proto.SearchFilesResult, error) {
	if a.Pattern == "" {
		return proto.SearchFilesResult{}, failf(proto.ErrBadRequest, "pattern is required, e.g. \"*.log\"")
	}
	if _, err := policy.MatchName(c.goos, a.Pattern, ""); err != nil {
		return proto.SearchFilesResult{}, failf(proto.ErrBadRequest, "bad pattern %q: %v", a.Pattern, err)
	}
	t, err := c.open(a.Path)
	if err != nil {
		return proto.SearchFilesResult{}, err
	}
	defer t.close()
	if !t.info.IsDir() {
		return proto.SearchFilesResult{}, failf(proto.ErrNotRegular, "%s is a file; search_files needs a directory", a.Path)
	}
	limit := clampLimit(a.Limit, c.caps.maxList)
	res := proto.SearchFilesResult{Matches: []proto.FileInfo{}}
	rules := c.allowRules()
	err = c.walk(t, walkDepth(a.MaxDepth), func(p, _ string, info fs.FileInfo, _ int) (bool, error) {
		res.Scanned++
		isDir := info.IsDir() && !isLink(info)
		if !policy.Decide(c.goos, rules, p, isDir).Allowed {
			return false, nil // hidden, and a denied directory is never entered
		}
		if ok, _ := policy.MatchName(c.goos, a.Pattern, info.Name()); ok {
			if len(res.Matches) == limit {
				res.Truncated = true
				return false, errStop
			}
			res.Matches = append(res.Matches, fileInfo(p, info))
		}
		return isDir, nil
	})
	if err != nil {
		return proto.SearchFilesResult{}, err
	}
	slices.SortFunc(res.Matches, func(a, b proto.FileInfo) int { return strings.Compare(a.Path, b.Path) })
	return res, nil
}
