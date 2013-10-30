package AES

import (
	"fmt"
	"testing"
)

func checkWord(funcName string, got, expect word, t *testing.T) {
	if got.b[0] != expect.b[0] {
		t.Errorf("(%s) 1st byte:: expected: %02x, got: %02x\n", 
			funcName, expect.b[0], got.b[0])
	}
	if got.b[1] != expect.b[1] {
		t.Errorf("(%s) 2nd byte:: expected: %02x, got: %02x\n", 
			funcName, expect.b[1], got.b[1])
	}
	if got.b[2] != expect.b[2] {
		t.Errorf("(%s) 3rd byte:: expected: %02x, got: %02x\n", 
			funcName, expect.b[2], got.b[2])
	}
	if got.b[3] != expect.b[3] {
		t.Errorf("(%s) 4th byte:: expected: %02x, got: %02x\n", 
			funcName, expect.b[3], got.b[3])
	}
}

func Test_subWord(t *testing.T) {
	w := word{b: [4]byte{0x32, 0x55, 0xf1, 0x2c}}
	sw := w.subWord()
	checkWord("subWord", word{b: [4]byte{0x23, 0xfc, 0xa1, 0x71}}, sw, t)
	fmt.Println("Test_subWord:\t\t\t\t\tPASS")
}

func Test_rotWord(t *testing.T) {
	w := word{b: [4]byte{0xfa, 0xec, 0x59, 0x06}}
	rw := w.rotWord()
	checkWord("rotWord", word{b: [4]byte{0xec, 0x59, 0x06, 0xfa}}, rw, t)
	fmt.Println("Test_rotWord:\t\t\t\t\tPASS")
}

func Test_xor(t *testing.T) {
	w1 := word{b: [4]byte{0x1a, 0x64, 0xf6, 0xb8}}
	w2 := word{b: [4]byte{0x26, 0x12, 0xd3, 0xf0}}
	xw := w1.xor(w2)
	checkWord("xor", word{b: [4]byte{0x3c, 0x76, 0x25, 0x48}}, xw, t)
	fmt.Println("Test_xor:\t\t\t\t\tPASS")
}

func Test_keyExpansion_128bit(t *testing.T) {
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}

	ekey := keyExpansion(key, 4, 10)

	checkWord("keyExpansion", word{b: [4]byte{0x2b, 0x7e, 0x15, 0x16}}, 
		ekey[0], t)
	checkWord("keyExpansion", word{b: [4]byte{0x28, 0xae, 0xd2, 0xa6}}, 
		ekey[1], t)
	checkWord("keyExpansion", word{b: [4]byte{0xab, 0xf7, 0x15, 0x88}}, 
		ekey[2], t)
	checkWord("keyExpansion", word{b: [4]byte{0x09, 0xcf, 0x4f, 0x3c}}, 
		ekey[3], t)
	checkWord("keyExpansion", word{b: [4]byte{0xa0, 0xfa, 0xfe, 0x17}}, 
		ekey[4], t)
	checkWord("keyExpansion", word{b: [4]byte{0x88, 0x54, 0x2c, 0xb1}}, 
		ekey[5], t)
	checkWord("keyExpansion", word{b: [4]byte{0x23, 0xa3, 0x39, 0x39}}, 
		ekey[6], t)
	checkWord("keyExpansion", word{b: [4]byte{0x2a, 0x6c, 0x76, 0x05}}, 
		ekey[7], t)
	checkWord("keyExpansion", word{b: [4]byte{0xf2, 0xc2, 0x95, 0xf2}}, 
		ekey[8], t)
	checkWord("keyExpansion", word{b: [4]byte{0x7a, 0x96, 0xb9, 0x43}}, 
		ekey[9], t)
	checkWord("keyExpansion", word{b: [4]byte{0x59, 0x35, 0x80, 0x7a}}, 
		ekey[10], t)
	checkWord("keyExpansion", word{b: [4]byte{0x73, 0x59, 0xf6, 0x7f}}, 
		ekey[11], t)
	checkWord("keyExpansion", word{b: [4]byte{0x3d, 0x80, 0x47, 0x7d}}, 
		ekey[12], t)
	checkWord("keyExpansion", word{b: [4]byte{0x47, 0x16, 0xfe, 0x3e}}, 
		ekey[13], t)
	checkWord("keyExpansion", word{b: [4]byte{0x1e, 0x23, 0x7e, 0x44}}, 
		ekey[14], t)
	checkWord("keyExpansion", word{b: [4]byte{0x6d, 0x7a, 0x88, 0x3b}}, 
		ekey[15], t)
	checkWord("keyExpansion", word{b: [4]byte{0xef, 0x44, 0xa5, 0x41}}, 
		ekey[16], t)
	checkWord("keyExpansion", word{b: [4]byte{0xa8, 0x52, 0x5b, 0x7f}}, 
		ekey[17], t)
	checkWord("keyExpansion", word{b: [4]byte{0xb6, 0x71, 0x25, 0x3b}}, 
		ekey[18], t)
	checkWord("keyExpansion", word{b: [4]byte{0xdb, 0x0b, 0xad, 0x00}}, 
		ekey[19], t)
	checkWord("keyExpansion", word{b: [4]byte{0xd4, 0xd1, 0xc6, 0xf8}}, 
		ekey[20], t)
	checkWord("keyExpansion", word{b: [4]byte{0x7c, 0x83, 0x9d, 0x87}}, 
		ekey[21], t)
	checkWord("keyExpansion", word{b: [4]byte{0xca, 0xf2, 0xb8, 0xbc}}, 
		ekey[22], t)
	checkWord("keyExpansion", word{b: [4]byte{0x11, 0xf9, 0x15, 0xbc}}, 
		ekey[23], t)
	checkWord("keyExpansion", word{b: [4]byte{0x6d, 0x88, 0xa3, 0x7a}}, 
		ekey[24], t)
	checkWord("keyExpansion", word{b: [4]byte{0x11, 0x0b, 0x3e, 0xfd}}, 
		ekey[25], t)
	checkWord("keyExpansion", word{b: [4]byte{0xdb, 0xf9, 0x86, 0x41}}, 
		ekey[26], t)
	checkWord("keyExpansion", word{b: [4]byte{0xca, 0x00, 0x93, 0xfd}}, 
		ekey[27], t)
	checkWord("keyExpansion", word{b: [4]byte{0x4e, 0x54, 0xf7, 0x0e}}, 
		ekey[28], t)
	checkWord("keyExpansion", word{b: [4]byte{0x5f, 0x5f, 0xc9, 0xf3}}, 
		ekey[29], t)
	checkWord("keyExpansion", word{b: [4]byte{0x84, 0xa6, 0x4f, 0xb2}}, 
		ekey[30], t)
	checkWord("keyExpansion", word{b: [4]byte{0x4e, 0xa6, 0xdc, 0x4f}}, 
		ekey[31], t)
	checkWord("keyExpansion", word{b: [4]byte{0xea, 0xd2, 0x73, 0x21}}, 
		ekey[32], t)
	checkWord("keyExpansion", word{b: [4]byte{0xb5, 0x8d, 0xba, 0xd2}}, 
		ekey[33], t)
	checkWord("keyExpansion", word{b: [4]byte{0x31, 0x2b, 0xf5, 0x60}}, 
		ekey[34], t)
	checkWord("keyExpansion", word{b: [4]byte{0x7f, 0x8d, 0x29, 0x2f}}, 
		ekey[35], t)
	checkWord("keyExpansion", word{b: [4]byte{0xac, 0x77, 0x66, 0xf3}}, 
		ekey[36], t)
	checkWord("keyExpansion", word{b: [4]byte{0x19, 0xfa, 0xdc, 0x21}}, 
		ekey[37], t)
	checkWord("keyExpansion", word{b: [4]byte{0x28, 0xd1, 0x29, 0x41}}, 
		ekey[38], t)
	checkWord("keyExpansion", word{b: [4]byte{0x57, 0x5c, 0x00, 0x6e}}, 
		ekey[39], t)
	checkWord("keyExpansion", word{b: [4]byte{0xd0, 0x14, 0xf9, 0xa8}}, 
		ekey[40], t)
	checkWord("keyExpansion", word{b: [4]byte{0xc9, 0xee, 0x25, 0x89}}, 
		ekey[41], t)
	checkWord("keyExpansion", word{b: [4]byte{0xe1, 0x3f, 0x0c, 0xc8}}, 
		ekey[42], t)
	checkWord("keyExpansion", word{b: [4]byte{0xb6, 0x63, 0x0c, 0xa6}}, 
		ekey[43], t)
	fmt.Println("Test_keyExpansion_128bit:\t\t\tPASS")
}

func Test_keyExpansion_196bit(t *testing.T) {
	key := []byte{0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
			0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
			0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b}

	ekey := keyExpansion(key, 6, 12)

	checkWord("keyExpansion", word{b: [4]byte{0x8e, 0x73, 0xb0, 0xf7}}, 
		ekey[0], t)
	checkWord("keyExpansion", word{b: [4]byte{0xda, 0x0e, 0x64, 0x52}}, 
		ekey[1], t)
	checkWord("keyExpansion", word{b: [4]byte{0xc8, 0x10, 0xf3, 0x2b}}, 
		ekey[2], t)
	checkWord("keyExpansion", word{b: [4]byte{0x80, 0x90, 0x79, 0xe5}}, 
		ekey[3], t)
	checkWord("keyExpansion", word{b: [4]byte{0x62, 0xf8, 0xea, 0xd2}}, 
		ekey[4], t)
	checkWord("keyExpansion", word{b: [4]byte{0x52, 0x2c, 0x6b, 0x7b}}, 
		ekey[5], t)
	fmt.Println("Test_keyExpansion_196bit:\t\t\tPASS")
}

func Test_keyExpansion_256bit(t *testing.T) {
	key := []byte{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
			0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
			0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
			0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}

	ekey := keyExpansion(key, 8, 14)

	checkWord("keyExpansion", word{b: [4]byte{0x60, 0x3d, 0xeb, 0x10}}, 
		ekey[0], t)
	checkWord("keyExpansion", word{b: [4]byte{0x15, 0xca, 0x71, 0xbe}}, 
		ekey[1], t)
	checkWord("keyExpansion", word{b: [4]byte{0x2b, 0x73, 0xae, 0xf0}}, 
		ekey[2], t)
	checkWord("keyExpansion", word{b: [4]byte{0x85, 0x7d, 0x77, 0x81}}, 
		ekey[3], t)
	checkWord("keyExpansion", word{b: [4]byte{0x1f, 0x35, 0x2c, 0x07}}, 
		ekey[4], t)
	checkWord("keyExpansion", word{b: [4]byte{0x3b, 0x61, 0x08, 0xd7}}, 
		ekey[5], t)
	checkWord("keyExpansion", word{b: [4]byte{0x2d, 0x98, 0x10, 0xa3}}, 
		ekey[6], t)
	checkWord("keyExpansion", word{b: [4]byte{0x09, 0x14, 0xdf, 0xf4}}, 
		ekey[7], t)
	fmt.Println("Test_keyExpansion_256bit:\t\t\tPASS")
}

func Test_subBytes(t *testing.T) {
	s := state{
		b: [4][4]byte{
			[4]byte{0x19, 0xa0, 0x9a, 0xe9},
			[4]byte{0x3d, 0xf4, 0xc6, 0xf8},
			[4]byte{0xe3, 0xe2, 0x8d, 0x48},
			[4]byte{0xbe, 0x2b, 0x2a, 0x08},
		},
	}

	s = s.subBytes()

	checkWord("subBytes", 
		word{b: [4]byte{s.b[0][0], s.b[0][1], s.b[0][2], s.b[0][3]}},
		word{b: [4]byte{0xd4, 0xe0, 0xb8, 0x1e}}, t)
	checkWord("subBytes", 
		word{b: [4]byte{s.b[1][0], s.b[1][1], s.b[1][2], s.b[1][3]}},
		word{b: [4]byte{0x27, 0xbf, 0xb4, 0x41}}, t)
	checkWord("subBytes", 
		word{b: [4]byte{s.b[2][0], s.b[2][1], s.b[2][2], s.b[2][3]}},
		word{b: [4]byte{0x11, 0x98, 0x5d, 0x52}}, t)
	checkWord("subBytes", 
		word{b: [4]byte{s.b[3][0], s.b[3][1], s.b[3][2], s.b[3][3]}},
		word{b: [4]byte{0xae, 0xf1, 0xe5, 0x30}}, t)
	fmt.Println("Test_subBytes:\t\t\t\t\tPASS")
}

func Test_invSubBytes(t *testing.T) {
	s := state{
		b: [4][4]byte{
			[4]byte{0xd4, 0xe0, 0xb8, 0x1e},
			[4]byte{0x27, 0xbf, 0xb4, 0x41},
			[4]byte{0x11, 0x98, 0x5d, 0x52},
			[4]byte{0xae, 0xf1, 0xe5, 0x30},
		},
	}

	s = s.invSubBytes()

	checkWord("subBytes", 
		word{b: [4]byte{s.b[0][0], s.b[0][1], s.b[0][2], s.b[0][3]}},
		word{b: [4]byte{0x19, 0xa0, 0x9a, 0xe9}}, t)
	checkWord("subBytes", 
		word{b: [4]byte{s.b[1][0], s.b[1][1], s.b[1][2], s.b[1][3]}},
		word{b: [4]byte{0x3d, 0xf4, 0xc6, 0xf8}}, t)
	checkWord("subBytes", 
		word{b: [4]byte{s.b[2][0], s.b[2][1], s.b[2][2], s.b[2][3]}},
		word{b: [4]byte{0xe3, 0xe2, 0x8d, 0x48}}, t)
	checkWord("subBytes", 
		word{b: [4]byte{s.b[3][0], s.b[3][1], s.b[3][2], s.b[3][3]}},
		word{b: [4]byte{0xbe, 0x2b, 0x2a, 0x08}}, t)
	fmt.Println("Test_invSubBytes:\t\t\t\tPASS")
}

func Test_shiftRows(t *testing.T) {
	s := state{
		b: [4][4]byte{
			[4]byte{0x52, 0x85, 0xe3, 0xf6},
			[4]byte{0x50, 0xa4, 0x11, 0xcf},
			[4]byte{0x2f, 0x5e, 0xc8, 0x6a},
			[4]byte{0x28, 0xd7, 0x07, 0x94},
		},
	}

	s = s.shiftRows()

	checkWord("shiftRows", 
		word{b: [4]byte{s.b[0][0], s.b[0][1], s.b[0][2], s.b[0][3]}},
		word{b: [4]byte{0x52, 0x85, 0xe3, 0xf6}}, t)
	checkWord("shiftRows", 
		word{b: [4]byte{s.b[1][0], s.b[1][1], s.b[1][2], s.b[1][3]}},
		word{b: [4]byte{0xa4, 0x11, 0xcf, 0x50}}, t)
	checkWord("shiftRows", 
		word{b: [4]byte{s.b[2][0], s.b[2][1], s.b[2][2], s.b[2][3]}},
		word{b: [4]byte{0xc8, 0x6a, 0x2f, 0x5e}}, t)
	checkWord("shiftRows", 
		word{b: [4]byte{s.b[3][0], s.b[3][1], s.b[3][2], s.b[3][3]}},
		word{b: [4]byte{0x94, 0x28, 0xd7, 0x07}}, t)
	fmt.Println("Test_shiftRows:\t\t\t\t\tPASS")
}

func Test_invShiftRows(t *testing.T) {
	s := state{
		b: [4][4]byte{
			[4]byte{0x52, 0x85, 0xe3, 0xf6},
			[4]byte{0xa4, 0x11, 0xcf, 0x50},
			[4]byte{0xc8, 0x6a, 0x2f, 0x5e},
			[4]byte{0x94, 0x28, 0xd7, 0x07},
		},
	}

	s = s.invShiftRows()

	checkWord("shiftRows", 
		word{b: [4]byte{s.b[0][0], s.b[0][1], s.b[0][2], s.b[0][3]}},
		word{b: [4]byte{0x52, 0x85, 0xe3, 0xf6}}, t)
	checkWord("shiftRows", 
		word{b: [4]byte{s.b[1][0], s.b[1][1], s.b[1][2], s.b[1][3]}},
		word{b: [4]byte{0x50, 0xa4, 0x11, 0xcf}}, t)
	checkWord("shiftRows", 
		word{b: [4]byte{s.b[2][0], s.b[2][1], s.b[2][2], s.b[2][3]}},
		word{b: [4]byte{0x2f, 0x5e, 0xc8, 0x6a}}, t)
	checkWord("shiftRows", 
		word{b: [4]byte{s.b[3][0], s.b[3][1], s.b[3][2], s.b[3][3]}},
		word{b: [4]byte{0x28, 0xd7, 0x07, 0x94}}, t)
	fmt.Println("Test_invShiftRows:\t\t\t\tPASS")
}

func Test_mixColumns(t *testing.T) {
	s := state{
		b: [4][4]byte{
			[4]byte{0xf7, 0x27, 0x9b, 0x54},
			[4]byte{0x83, 0x43, 0xb5, 0xab},
			[4]byte{0x40, 0x3d, 0x31, 0xa9},
			[4]byte{0x3f, 0xf0, 0xff, 0xd3},
		},
	}

	s = s.mixColumns()

	checkWord("mixColumns", 
		word{b: [4]byte{s.b[0][0], s.b[0][1], s.b[0][2], s.b[0][3]}},
		word{b: [4]byte{0x14, 0x46, 0x27, 0x34}}, t)
	checkWord("mixColumns", 
		word{b: [4]byte{s.b[1][0], s.b[1][1], s.b[1][2], s.b[1][3]}},
		word{b: [4]byte{0x15, 0x16, 0x46, 0x2a}}, t)
	checkWord("mixColumns", 
		word{b: [4]byte{s.b[2][0], s.b[2][1], s.b[2][2], s.b[2][3]}},
		word{b: [4]byte{0xb5, 0x15, 0x56, 0xd8}}, t)
	checkWord("mixColumns", 
		word{b: [4]byte{s.b[3][0], s.b[3][1], s.b[3][2], s.b[3][3]}},
		word{b: [4]byte{0xbf, 0xec, 0xd7, 0x43}}, t)
	fmt.Println("Test_mixColumns:\t\t\t\tPASS")
}

func Test_invMixColumnsState(t *testing.T) {
	s := state{
		b: [4][4]byte{
			[4]byte{0x14, 0x46, 0x27, 0x34},
			[4]byte{0x15, 0x16, 0x46, 0x2a},
			[4]byte{0xb5, 0x15, 0x56, 0xd8},
			[4]byte{0xbf, 0xec, 0xd7, 0x43},
		},
	}

	s = s.invMixColumns()

	checkWord("mixColumns", 
		word{b: [4]byte{s.b[0][0], s.b[0][1], s.b[0][2], s.b[0][3]}},
		word{b: [4]byte{0xf7, 0x27, 0x9b, 0x54}}, t)
	checkWord("mixColumns", 
		word{b: [4]byte{s.b[1][0], s.b[1][1], s.b[1][2], s.b[1][3]}},
		word{b: [4]byte{0x83, 0x43, 0xb5, 0xab}}, t)
	checkWord("mixColumns", 
		word{b: [4]byte{s.b[2][0], s.b[2][1], s.b[2][2], s.b[2][3]}},
		word{b: [4]byte{0x40, 0x3d, 0x31, 0xa9}}, t)
	checkWord("mixColumns", 
		word{b: [4]byte{s.b[3][0], s.b[3][1], s.b[3][2], s.b[3][3]}},
		word{b: [4]byte{0x3f, 0xf0, 0xff, 0xd3}}, t)
	fmt.Println("Test_invMixColumns:\t\t\t\tPASS")
}

func Test_invMixColumnsWordArray(t *testing.T) {
	// TODO
}

func Test_addRoundKey(t *testing.T) {
	s := state{
		b: [4][4]byte{
			[4]byte{0x32, 0x88, 0x31, 0xe0},
			[4]byte{0x43, 0x5a, 0x31, 0x37},
			[4]byte{0xf6, 0x30, 0x98, 0x07},
			[4]byte{0xa8, 0x8d, 0xa2, 0x34},
		},
	}

	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}

	w := keyExpansion(key, 4, 10)

	s = s.addRoundKey(w, 0)

	checkWord("addRoundKey", 
		word{b: [4]byte{s.b[0][0], s.b[0][1], s.b[0][2], s.b[0][3]}},
		word{b: [4]byte{0x19, 0xa0, 0x9a, 0xe9}}, t)
	checkWord("addRoundKey", 
		word{b: [4]byte{s.b[1][0], s.b[1][1], s.b[1][2], s.b[1][3]}},
		word{b: [4]byte{0x3d, 0xf4, 0xc6, 0xf8}}, t)
	checkWord("addRoundKey", 
		word{b: [4]byte{s.b[2][0], s.b[2][1], s.b[2][2], s.b[2][3]}},
		word{b: [4]byte{0xe3, 0xe2, 0x8d, 0x48}}, t)
	checkWord("addRoundKey", 
		word{b: [4]byte{s.b[3][0], s.b[3][1], s.b[3][2], s.b[3][3]}},
		word{b: [4]byte{0xbe, 0x2b, 0x2a, 0x08}}, t)
	fmt.Println("Test_addRoundKey:\t\t\t\tPASS")
}

func Test_cipher(t *testing.T) {
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}

	in := []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
			0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}

	out := cipher(in, keyExpansion(key, 4, 10), 10)

	correct := []byte{0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
				0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32}

	for i := 0; i < 16; i++ {
		if out[i] != correct[i] {
			t.Errorf("(cipher) expected %02x, got %02x\n", 
				correct[i], out[i])
		}
	}

	fmt.Println("Test_cipher:\t\t\t\t\tPASS")
}

func Test_invCipher(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

	in := []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
			0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}

	out := invCipher(in, keyExpansion(key, 4, 10), 10)

	correct := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	for i := 0; i < 16; i++ {
		if out[i] != correct[i] {
			t.Errorf("(cipher) expected %02x, got %02x\n", 
				correct[i], out[i])
		}
	}

	fmt.Println("Test_invCipher:\t\t\t\t\tPASS")
}

func Test_eqInvCipher(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

	in := []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
			0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}

	out := eqInvCipher(in, invKeyExpansion(key, 4, 10), 10)

	correct := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	for i := 0; i < 16; i++ {
		if out[i] != correct[i] {
			t.Errorf("(cipher) expected %02x, got %02x\n", 
				correct[i], out[i])
		}
	}

	fmt.Println("Test_eqInvCipher:\t\t\t\tPASS")
}

func Test_Encrypt_Decrypt_CBC(t *testing.T) {
        key, err := GenerateKey(16)
        if err == nil {
		msg := "Banks likes to roll around like a monkey!"
		cipher, IV, err := Encrypt(msg, key, nil, "CBC")

		if err == nil {
			plain, _ := Decrypt(cipher, key, IV, nil, "CBC")
							
			if string(plain)[:41] != 
				"Banks likes to roll around like a monkey!" {
				t.Error("Test_Encrypt_Decrypt_CBC failed!")	
			}
		} else {
			t.Error("Test_Encrypt_Decrypt_CBC failed!")
		}
	} else {
		t.Error(err.Error())
	}
		
	fmt.Println("Test_Encrypt_Decrypt_CBC:\t\t\tPASS")
}

func Test_Encrypt_Decrypt_CTR(t *testing.T) {
        key, err := GenerateKey(16)
        if err == nil {
		msg := "Banks likes to roll around like a monkey!"
		cipher, IV, err := Encrypt(msg, key, incCtr, "CTR")

		if err == nil {
			plain, _ := Decrypt(cipher, key, IV, incCtr, "CTR")
							
			if string(plain)[:41] != 
				"Banks likes to roll around like a monkey!" {
				t.Error("Test_Encrypt_Decrypt_CTR failed!")	
			}
		} else {
			t.Error("Test_Encrypt_Decrypt_CTR failed!")
		}
	} else {
		t.Error(err.Error())
	}
		
	fmt.Println("Test_Encrypt_Decrypt_CTR:\t\t\tPASS")
}

