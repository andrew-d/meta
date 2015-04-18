package ssdeep

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFuzzyHasher(t *testing.T) {
	f1 := NewFuzzyHasher()
	f1.AddString("foobar")
	v1 := f1.Sum()

	f2 := NewFuzzyHasher()
	f2.AddString("foobar")
	v2 := f2.Sum()

	assert.Equal(t, v1, v2, "fuzzy hashes should match")

	f2.AddString("1")
	assert.NotEqual(t, v1, f2.Sum())
}
