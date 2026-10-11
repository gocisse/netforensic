package web

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDist(t *testing.T) {
	fsys, err := Dist()
	require.NoError(t, err)

	// rooted at the contents of dist: the tracked placeholder is at the top
	// level, and index.html too once the frontend has been built
	_, err = fs.Stat(fsys, ".gitkeep")
	assert.NoError(t, err, "dist always holds a placeholder so that the module compiles on a fresh clone")
	_, err = fs.Stat(fsys, "dist")
	assert.Error(t, err, "the dist directory itself is not part of the tree")
}
