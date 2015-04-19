package filesim

import (
	"fmt"
)

const (
	NUM_BLOCKHASHES = 31
	MIN_BLOCKSIZE   = 3
	SPAMSUM_LENGTH  = 10
	HASH_INIT       = 0x28021967
	HASH_PRIME      = 0x01000193
)

type blockhashContext struct {
	h          uint32
	halfh      uint32
	digest     [SPAMSUM_LENGTH]byte
	halfdigest byte
	dlen       uint
}

type FuzzyState struct {
	bhStart, bhEnd uint32
	bhContexts     [NUM_BLOCKHASHES]blockhashContext
	totalSize      uint32
	rollState      *RollingHasher
}

func tassert(b bool) {
	if !b {
		panic("Assertion failed")
	}
}

func NewFuzzyState() *FuzzyState {
	ret := &FuzzyState{
		bhStart:   0,
		bhEnd:     1,
		totalSize: 0,
		rollState: NewRollingHasher(),
	}
	ret.bhContexts[0] = blockhashContext{
		h:     HASH_INIT,
		halfh: HASH_INIT,
		dlen:  0,
	}
	return ret
}

func (s *FuzzyState) tryForkBlockhash() {
	if s.bhEnd >= NUM_BLOCKHASHES {
		return
	}

	tassert(s.bhEnd > 0)

	oldBlockhash := &s.bhContexts[s.bhEnd-1]
	newBlochash := &s.bhContexts[s.bhEnd]

	newBlochash.h = oldBlockhash.h
	newBlochash.halfh = oldBlockhash.halfh
	newBlochash.digest[0] = 0
	newBlochash.halfdigest = 0
	newBlochash.dlen = 0

	s.bhEnd++
}

func ssdeep_bs(i uint32) uint32 {
	return MIN_BLOCKSIZE << i
}

func (s *FuzzyState) tryReduceBlockhash() {
	tassert(s.bhStart < s.bhEnd)
	if s.bhEnd-s.bhStart < 2 {
		// Need at least two working hashes
		return
	}

	if ssdeep_bs(s.bhStart)*SPAMSUM_LENGTH >= s.totalSize {
		// Initial blocksize estimate would select this or a smaller blocksize.
		return
	}

	if s.bhContexts[s.bhStart+1].dlen < (SPAMSUM_LENGTH / 2) {
		// Estimate adjustment would select this blocksize
		return
	}

	s.bhStart++
}

func sumHash(c byte, h uint32) uint32 {
	return (h * HASH_PRIME) ^ uint32(c)
}

var b64 = `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`

func (s *FuzzyState) fuzzyEngineStep(b byte) {
	// At each character we update the rolling hash and the normal hashes.
	// When the rolling hash hits a reset value then we emit a normal hash
	// as a element of the signature and reset the normal hash.
	s.rollState.AddByte(b)
	h := s.rollState.Sum()

	for i := s.bhStart; i < s.bhEnd; i++ {
		s.bhContexts[i].h = sumHash(b, s.bhContexts[i].h)
		s.bhContexts[i].halfh = sumHash(b, s.bhContexts[i].halfh)
	}

	for i := s.bhStart; i < s.bhEnd; i++ {
		if h%ssdeep_bs(i) != ssdeep_bs(i)-1 {
			break
		}

		// We have hit a reset point. We now emit hashes which are
		// based on all characters in the piece of the message between
		// the last reset point and this one.
		if s.bhContexts[i].dlen == 0 {
			s.tryForkBlockhash()
		}

		s.bhContexts[i].digest[s.bhContexts[i].dlen] = b64[s.bhContexts[i].h%64]
		s.bhContexts[i].halfdigest = b64[s.bhContexts[i].halfh%64]

		if s.bhContexts[i].dlen < SPAMSUM_LENGTH-1 {
			// We can have a problem with the tail overflowing. The
			// easiest way to cope with this is to only reset the
			// normal hash if we have room for more characters in
			// our signature. This has the effect of combining the
			// last few pieces of the message into a single piece
			s.bhContexts[i].dlen += 1
			s.bhContexts[i].digest[s.bhContexts[i].dlen] = '\x00'

			if s.bhContexts[i].dlen < SPAMSUM_LENGTH/2 {
				s.bhContexts[i].halfh = HASH_INIT
				s.bhContexts[i].halfdigest = 0
			}
		} else {
			s.tryReduceBlockhash()
		}
	}
}

func (s *FuzzyState) Update(b []byte) {
	// TODO: check for integer overflow
	s.totalSize += uint32(len(b))
	for _, ch := range b {
		s.fuzzyEngineStep(ch)
	}
}

func (s *FuzzyState) Digest() (ret string) {
	bi := s.bhStart
	h := s.rollState.Sum()

	tassert(bi == 0 || (ssdeep_bs(bi)/2*SPAMSUM_LENGTH < s.totalSize))

	// Initial blocksize guess
	fmt.Printf("blocksize guess = %d\n", bi)
	for ssdeep_bs(bi)*SPAMSUM_LENGTH < s.totalSize {
		bi++
		if bi >= NUM_BLOCKHASHES {
			// TODO: Overflow
			panic("overflow")
		}
	}

	// Adapt blocksize guess to actual digest length
	for bi >= s.bhEnd {
		bi--
	}
	for bi > s.bhStart && s.bhContexts[bi].dlen < SPAMSUM_LENGTH/2 {
		bi--
	}
	fmt.Printf("final blocksize guess = %d\n", bi)

	tassert(!(bi > 0 && s.bhContexts[bi].dlen < SPAMSUM_LENGTH/2))

	ret = fmt.Sprintf("%d:", ssdeep_bs(bi))

	i := s.bhContexts[bi].dlen
	ret += string(s.bhContexts[bi].digest[:])

	if h != 0 {
		ret += string(b64[s.bhContexts[bi].h%64])
	} else if s.bhContexts[bi].digest[s.bhContexts[bi].dlen] != '\x00' {
		ret += string(s.bhContexts[bi].digest[i])
	}
	ret += ":"

	if bi < s.bhEnd-1 {
		bi++

		ret += string(s.bhContexts[bi].digest[:])
		if h != 0 {
			ret += string(b64[s.bhContexts[bi].halfh%64])
		} else {
			i := s.bhContexts[bi].halfdigest
			if i != '\x00' {
				ret += string(i)
			}
		}

	} else if h != 0 {
		ret += string(b64[s.bhContexts[bi].h%64])
	}

	return
}

func (s *FuzzyState) Write(buf []byte) (int, error) {
	s.Update(buf)
	return len(buf), nil
}
