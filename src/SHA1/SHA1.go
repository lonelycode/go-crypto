package SHA1

import (
	"encoding/binary"
)

// Pad the message so that its length is a multiple of 512 bits
// (see FIPS PUB 180-4, 5.1.1)
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

// Parse the message into N 512-bit blocks
// (see FIPS PUB 180-4, 5.2.1)
func parse(M []byte) (int, []block) {
	N := len(M) / 64
	blocks := make([]block, N)
	for i := 0; i < N*16; i += 16 {
		blocks[i/16] = block{
			[]word{
				word{M[i*4 : i*4+4]}, word{M[i*4+4 : i*4+8]},
				word{M[i*4+8 : i*4+12]}, word{M[i*4+12 : i*4+16]},
				word{M[i*4+16 : i*4+20]}, word{M[i*4+20 : i*4+24]},
				word{M[i*4+24 : i*4+28]}, word{M[i*4+28 : i*4+32]},
				word{M[i*4+32 : i*4+36]}, word{M[i*4+36 : i*4+40]},
				word{M[i*4+40 : i*4+44]}, word{M[i*4+44 : i*4+48]},
				word{M[i*4+48 : i*4+52]}, word{M[i*4+52 : i*4+56]},
				word{M[i*4+56 : i*4+60]}, word{M[i*4+60 : i*4+64]},
			},
		}
	}

	return N, blocks
}

// K constants (see FIPS PUB 180-4, 4.2.1)
func K(t int) word {
	if t >= 0 && t <= 19 {
		return word{[]byte{0x5a, 0x82, 0x79, 0x99}}
	} else if t >= 20 && t <= 39 {
		return word{[]byte{0x6e, 0xd9, 0xeb, 0xa1}}
	} else if t >= 40 && t <= 59 {
		return word{[]byte{0x8f, 0x1b, 0xbc, 0xdc}}
	} else if t >= 60 && t <= 79 {
		return word{[]byte{0xca, 0x62, 0xc1, 0xd6}}
	}
	panic("Illegal t!")
}

// Preprocessing (see FIPS PUB 180-4, 6.1.1)
func New(M string) Hash {
	h := Hash{}

	// Hash value (initialized as per FIPS PUB 180-4, 5.3.1)
	h.digest = value{
		[]word{
			word{[]byte{0x67, 0x45, 0x23, 0x01}},
			word{[]byte{0xef, 0xcd, 0xab, 0x89}},
			word{[]byte{0x98, 0xba, 0xdc, 0xfe}},
			word{[]byte{0x10, 0x32, 0x54, 0x76}},
			word{[]byte{0xc3, 0xd2, 0xe1, 0xf0}},
		},
	}

	// Parse and pad the message
	h.N, h.M = parse(pad([]byte(M)))

	return h
}

// Compute the hash value (see FIPS PUB 180-4, 6.1.2)
func (h *Hash) Digest() {
	for i := 1; i <= h.N; i++ {
		// Prepare the message schedule, {W_t}}
		W := make([]word, 80)
		for t := 0; t <= 15; t++ {
			W[t] = h.M[i-1].w[t]
		}
		for t := 16; t <= 79; t++ {
			W[t] = rotl(xor(xor(W[t-3], W[t-8]), xor(W[t-14], W[t-16])), 1)
		}

		// Initialize the five working variables, a, b, c, d, and e, with the
		// (i-1)st hash value
		a := h.digest.w[0]
		b := h.digest.w[1]
		c := h.digest.w[2]
		d := h.digest.w[3]
		e := h.digest.w[4]

		// Do some rotations
		for t := 0; t <= 79; t++ {
			T := add(add(add(rotl(a, 5), f(b, c, d, t)), add(e, K(t))), W[t])
			e = d
			d = c
			c = rotl(b, 30)
			b = a
			a = T
		}

		// Compute the ith intermediate hash value H_i
		h.digest.w[0] = add(a, h.digest.w[0])
		h.digest.w[1] = add(b, h.digest.w[1])
		h.digest.w[2] = add(c, h.digest.w[2])
		h.digest.w[3] = add(d, h.digest.w[3])
		h.digest.w[4] = add(e, h.digest.w[4])
	}
}
