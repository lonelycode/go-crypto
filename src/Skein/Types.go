package Skein

type word uint64

// Circular shift left
func (w word) rotl(shift uint) word {
	return (w << shift) | (w >> (64 - shift))
}

type Threefish struct {
	Nw, Nr, Size uint
	R            [][]uint
	PI           []uint
}

type Skein struct {
	Nb, No uint
	C      []byte
}
