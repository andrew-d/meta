package ssdeep

import (
	"io"
)

const ROLLING_WINDOW = 7

type FuzzyHasher struct {
	window     [ROLLING_WINDOW]byte
	h1, h2, h3 uint32
	n          int
}

func NewFuzzyHasher() *FuzzyHasher {
	return &FuzzyHasher{}
}

func (h *FuzzyHasher) AddBytes(bytes []byte) {
	for _, c := range bytes {
		h.h2 -= h.h1
		h.h2 += ROLLING_WINDOW * uint32(c)

		h.h1 += uint32(c)
		h.h1 -= uint32(h.window[h.n%ROLLING_WINDOW])

		h.window[h.n%ROLLING_WINDOW] = c
		h.n++

		h.h3 <<= 5
		h.h3 ^= uint32(c)
	}
}

func (h *FuzzyHasher) AddString(s string) {
	h.AddBytes([]byte(s))
}

func (h *FuzzyHasher) Write(b []byte) (int, error) {
	h.AddBytes(b)
	return len(b), nil
}

func (h *FuzzyHasher) Sum() uint32 {
	return h.h1 + h.h2 + h.h3
}

var _ io.Writer = &FuzzyHasher{}
