package filesim

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFuzzyHash(t *testing.T) {
	f, err := os.Open(`An Efficient Similarity Digests Database Lookup.pdf`)
	assert.NoError(t, err)

	s := NewFuzzyState()
	io.Copy(s, f)

	///fmt.Printf("state = %#v\n", s)
	out := s.Digest()
	fmt.Println(out)
}
