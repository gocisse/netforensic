package server

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGCGovernor(t *testing.T) {
	orig := debug.SetGCPercent(100)
	defer debug.SetGCPercent(orig)
	current := func() int { p := debug.SetGCPercent(-2); debug.SetGCPercent(p); return p }

	var g gcGovernor
	first := g.lower()
	assert.Equal(t, bigGCPercent, current(), "the first big analysis lowers it")
	second := g.lower()
	assert.Equal(t, bigGCPercent, current())

	first()
	first() // ending twice must not end the other analysis too
	assert.Equal(t, bigGCPercent, current(), "still lowered while another analysis runs")
	second()
	assert.Equal(t, 100, current(), "the last one to finish restores the original")

	third := g.lower()
	assert.Equal(t, bigGCPercent, current(), "it can be lowered again later")
	third()
	assert.Equal(t, 100, current())
}
