package SHA1

import (
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

func Test_pad_one_block(t *testing.T) {
	M := []byte{0x61, 0x62, 0x63} // "abc"
	p := parse(pad(M))

	checkWord("Test_pad", p[0].GetWord(0), word{[4]byte{0x61, 0x62, 0x63, 0x80}}, t)
	checkWord("Test_pad", p[0].GetWord(1), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(2), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(3), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(4), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(5), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(6), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(7), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(8), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(9), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(10), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(11), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(12), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(13), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(14), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(15), word{[4]byte{0x00, 0x00, 0x00, 0x18}}, t)
}

func Test_pad_two_blocks(t *testing.T) {
	// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
	M := []byte{
		0x61, 0x62, 0x63, 0x64,
		0x62, 0x63, 0x64, 0x65,
		0x63, 0x64, 0x65, 0x66,
		0x64, 0x65, 0x66, 0x67,
		0x65, 0x66, 0x67, 0x68,
		0x66, 0x67, 0x68, 0x69,
		0x67, 0x68, 0x69, 0x6a,
		0x68, 0x69, 0x6a, 0x6b,
		0x69, 0x6a, 0x6b, 0x6c,
		0x6a, 0x6b, 0x6c, 0x6d,
		0x6b, 0x6c, 0x6d, 0x6e,
		0x6c, 0x6d, 0x6e, 0x6f,
		0x6d, 0x6e, 0x6f, 0x70,
		0x6e, 0x6f, 0x70, 0x71,
	}
	p := parse(pad(M))

	checkWord("Test_pad", p[0].GetWord(0), word{[4]byte{0x61, 0x62, 0x63, 0x64}}, t)
	checkWord("Test_pad", p[0].GetWord(1), word{[4]byte{0x62, 0x63, 0x64, 0x65}}, t)
	checkWord("Test_pad", p[0].GetWord(2), word{[4]byte{0x63, 0x64, 0x65, 0x66}}, t)
	checkWord("Test_pad", p[0].GetWord(3), word{[4]byte{0x64, 0x65, 0x66, 0x67}}, t)
	checkWord("Test_pad", p[0].GetWord(4), word{[4]byte{0x65, 0x66, 0x67, 0x68}}, t)
	checkWord("Test_pad", p[0].GetWord(5), word{[4]byte{0x66, 0x67, 0x68, 0x69}}, t)
	checkWord("Test_pad", p[0].GetWord(6), word{[4]byte{0x67, 0x68, 0x69, 0x6a}}, t)
	checkWord("Test_pad", p[0].GetWord(7), word{[4]byte{0x68, 0x69, 0x6a, 0x6b}}, t)
	checkWord("Test_pad", p[0].GetWord(8), word{[4]byte{0x69, 0x6a, 0x6b, 0x6c}}, t)
	checkWord("Test_pad", p[0].GetWord(9), word{[4]byte{0x6a, 0x6b, 0x6c, 0x6d}}, t)
	checkWord("Test_pad", p[0].GetWord(10), word{[4]byte{0x6b, 0x6c, 0x6d, 0x6e}}, t)
	checkWord("Test_pad", p[0].GetWord(11), word{[4]byte{0x6c, 0x6d, 0x6e, 0x6f}}, t)
	checkWord("Test_pad", p[0].GetWord(12), word{[4]byte{0x6d, 0x6e, 0x6f, 0x70}}, t)
	checkWord("Test_pad", p[0].GetWord(13), word{[4]byte{0x6e, 0x6f, 0x70, 0x71}}, t)
	checkWord("Test_pad", p[0].GetWord(14), word{[4]byte{0x80, 0x00, 0x00, 0x00}}, t)
	checkWord("Test_pad", p[0].GetWord(15), word{[4]byte{0x00, 0x00, 0x00, 0x00}}, t)
}
