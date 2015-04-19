package filesim

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRollingHasher(t *testing.T) {
	f1 := NewRollingHasher()
	f1.AddString("foobar")
	v1 := f1.Sum()

	f2 := NewRollingHasher()
	f2.AddString("foobar")
	v2 := f2.Sum()

	assert.Equal(t, v1, v2, "rolling hashes should match")

	f2.AddString("1")
	assert.NotEqual(t, v1, f2.Sum())
}
