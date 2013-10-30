package SHA1

import (
	"encoding/binary"
)

// SHA-1 words are 32-bits
type word struct {
	b [4]byte
}

// SHA-1 hash values are 160-bits (5 32-bit words)
type value struct {
	w [5]word
}

// SHA-1 blocks are 512-bits (16 32-bit words)
type block struct {
	w [16]word
}

func (b *block) GetWord(ndx int) word {
	return b.w[ndx]
}

func pad(M []byte) []byte {
	var l uint64 = uint64(len(M))

	// Start with a 1 bit
	M = append(M, 0x80)

	// Next comes 0 <= k < 512 0 bits so that the total message length is
	// congruent to 448 mod 512
	numZeroes := (56 - (l+1)%64) % 64
	for i := uint64(0); i < numZeroes; i++ {
		M = append(M, 0x00)
	}

	// Add the message length, in bits (Big Endian, please), to the end
	messageLen := make([]byte, 8)
	binary.BigEndian.PutUint64(messageLen, 8*l)
	M = append(M, messageLen[:]...)

	return M
}

func parse(M []byte) []block {
	N := len(M) / 64
	blocks := make([]block, N)
	for i := 0; i < N; i += 16 {
		blocks[i] = block{
			[16]word{
				word{[4]byte{M[i*4+0], M[i*4+1], M[i*4+2], M[i*4+3]}},
				word{[4]byte{M[i*4+4], M[i*4+5], M[i*4+6], M[i*4+7]}},
				word{[4]byte{M[i*4+8], M[i*4+9], M[i*4+10], M[i*4+11]}},
				word{[4]byte{M[i*4+12], M[i*4+13], M[i*4+14], M[i*4+15]}},
				word{[4]byte{M[i*4+16], M[i*4+17], M[i*4+18], M[i*4+19]}},
				word{[4]byte{M[i*4+20], M[i*4+21], M[i*4+22], M[i*4+23]}},
				word{[4]byte{M[i*4+24], M[i*4+25], M[i*4+26], M[i*4+27]}},
				word{[4]byte{M[i*4+28], M[i*4+29], M[i*4+30], M[i*4+31]}},
				word{[4]byte{M[i*4+32], M[i*4+33], M[i*4+34], M[i*4+35]}},
				word{[4]byte{M[i*4+36], M[i*4+37], M[i*4+38], M[i*4+39]}},
				word{[4]byte{M[i*4+40], M[i*4+41], M[i*4+42], M[i*4+43]}},
				word{[4]byte{M[i*4+44], M[i*4+45], M[i*4+46], M[i*4+47]}},
				word{[4]byte{M[i*4+48], M[i*4+49], M[i*4+50], M[i*4+51]}},
				word{[4]byte{M[i*4+52], M[i*4+53], M[i*4+54], M[i*4+55]}},
				word{[4]byte{M[i*4+56], M[i*4+57], M[i*4+58], M[i*4+59]}},
				word{[4]byte{M[i*4+60], M[i*4+61], M[i*4+62], M[i*4+63]}},
			},
		}
	}

	return blocks
}

// Initial hash value
var H0 value = value{
	[5]word{
		word{[4]byte{0x67, 0x45, 0x23, 0x01}},
		word{[4]byte{0xef, 0xcd, 0xab, 0x89}},
		word{[4]byte{0x98, 0xba, 0xdc, 0xfe}},
		word{[4]byte{0x10, 0x32, 0x54, 0x76}},
		word{[4]byte{0xc3, 0xd2, 0xe1, 0xf0}},
	},
}
