package filesim

import (
	"io"
)

const ROLLING_WINDOW = 7

type RollingHasher struct {
	window     [ROLLING_WINDOW]byte
	h1, h2, h3 uint32
	n          int
}

func NewRollingHasher() *RollingHasher {
	return &RollingHasher{}
}

func (h *RollingHasher) AddBytes(bytes []byte) {
	for _, c := range bytes {
		h.AddByte(c)
	}
}

func (h *RollingHasher) AddString(s string) {
	h.AddBytes([]byte(s))
}

func (h *RollingHasher) AddByte(c byte) {
	h.h2 -= h.h1
	h.h2 += ROLLING_WINDOW * uint32(c)

	h.h1 += uint32(c)
	h.h1 -= uint32(h.window[h.n%ROLLING_WINDOW])

	h.window[h.n%ROLLING_WINDOW] = c
	h.n++

	h.h3 <<= 5
	h.h3 ^= uint32(c)
}

func (h *RollingHasher) Write(b []byte) (int, error) {
	h.AddBytes(b)
	return len(b), nil
}

func (h *RollingHasher) Sum() uint32 {
	return h.h1 + h.h2 + h.h3
}

var _ io.Writer = &RollingHasher{}
