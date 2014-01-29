package Tiger

import (
	"encoding/binary"
)

// Pad the message so that its length is a multiple of 512 bits
func pad(M []byte) []byte {
	var l uint64 = uint64(len(M))

	// Start with a 1 bit
	M = append(M, byte(0x01))

	// Next comes 0 <= k < 512 0 bits so that the total message length is
	// congruent to 448 mod 512
	numZeroes := (56 - (l+1)%64) % 64
	for i := uint64(0); i < numZeroes; i++ {
		M = append(M, 0x00)
	}

	// Add the message length, in bits (Little Endian, please), to the end
	messageLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(messageLen, 8*l)
	M = append(M, messageLen[:]...)

	return M
}

// Parse the message into N 512-bit blocks
func parse(M []byte) (int, []block) {
	N := len(M) / 64
	blocks := make([]block, N)
	for i := 0; i < N; i++ {
		x0 := binary.LittleEndian.Uint64(M[i*64+0 : i*64+8])
		x1 := binary.LittleEndian.Uint64(M[i*64+8 : i*64+16])
		x2 := binary.LittleEndian.Uint64(M[i*64+16 : i*64+24])
		x3 := binary.LittleEndian.Uint64(M[i*64+24 : i*64+32])
		x4 := binary.LittleEndian.Uint64(M[i*64+32 : i*64+40])
		x5 := binary.LittleEndian.Uint64(M[i*64+40 : i*64+48])
		x6 := binary.LittleEndian.Uint64(M[i*64+48 : i*64+56])
		x7 := binary.LittleEndian.Uint64(M[i*64+56 : i*64+64])

		blocks[i] = block{[8]uint64{x0, x1, x2, x3, x4, x5, x6, x7}}
	}

	return N, blocks
}

// Initialize a new hash, setting the register variables to the correct
// start values.
func New(M string) Hash {
	h := Hash{}

	h.digest = value{
		0x0123456789ABCDEF,
		0xFEDCBA9876543210,
		0xF096A5B4C3B2E187,
		0,
		0,
		0,
	}

	// Parse and pad the message
	h.N, h.M = parse(pad([]byte(M)))

	return h
}

func (h *Hash) save_abc() {
	h.digest.aa = h.digest.a
	h.digest.bb = h.digest.b
	h.digest.cc = h.digest.c
}

func round(a, b, c *uint64, x, mul uint64) {
	*c ^= x

	c_0 := (*c >> (0 * 8)) & 0xFF
	c_1 := (*c >> (1 * 8)) & 0xFF
	c_2 := (*c >> (2 * 8)) & 0xFF
	c_3 := (*c >> (3 * 8)) & 0xFF
	c_4 := (*c >> (4 * 8)) & 0xFF
	c_5 := (*c >> (5 * 8)) & 0xFF
	c_6 := (*c >> (6 * 8)) & 0xFF
	c_7 := (*c >> (7 * 8)) & 0xFF

	*a -= t1[c_0] ^ t2[c_2] ^ t3[c_4] ^ t4[c_6]
	*b += t4[c_1] ^ t3[c_3] ^ t2[c_5] ^ t1[c_7]
	*b *= mul
}

func pass(a, b, c *uint64, mul uint64, x block) {
	round(a, b, c, x.x[0], mul)
	round(b, c, a, x.x[1], mul)
	round(c, a, b, x.x[2], mul)
	round(a, b, c, x.x[3], mul)
	round(b, c, a, x.x[4], mul)
	round(c, a, b, x.x[5], mul)
	round(a, b, c, x.x[6], mul)
	round(b, c, a, x.x[7], mul)
}

func key_schedule(x *block) {
	x.x[0] -= x.x[7] ^ 0xA5A5A5A5A5A5A5A5
	x.x[1] ^= x.x[0]
	x.x[2] += x.x[1]
	x.x[3] -= x.x[2] ^ (^(x.x[1]) << 19)
	x.x[4] ^= x.x[3]
	x.x[5] += x.x[4]
	x.x[6] -= x.x[5] ^ (^(x.x[4]) >> 23)
	x.x[7] ^= x.x[6]
	x.x[0] += x.x[7]
	x.x[1] -= x.x[0] ^ (^(x.x[7]) << 19)
	x.x[2] ^= x.x[1]
	x.x[3] += x.x[2]
	x.x[4] -= x.x[3] ^ (^(x.x[2]) >> 23)
	x.x[5] ^= x.x[4]
	x.x[6] += x.x[5]
	x.x[7] -= x.x[6] ^ 0x0123456789ABCDEF
}

func (h *Hash) feedforward() {
	h.digest.a ^= h.digest.aa
	h.digest.b -= h.digest.bb
	h.digest.c += h.digest.cc
}

// Compute the hash value (see FIPS PUB 180-4, 6.1.2)
func (h *Hash) Sum() {
	for i := 0; i < h.N; i++ {
		h.save_abc()
		pass(&(h.digest.a), &(h.digest.b), &(h.digest.c), 5, h.M[i])
		key_schedule(&(h.M[i]))
		pass(&(h.digest.c), &(h.digest.a), &(h.digest.b), 7, h.M[i])
		key_schedule(&(h.M[i]))
		pass(&(h.digest.b), &(h.digest.c), &(h.digest.a), 9, h.M[i])
		h.feedforward()
	}
}
