package SHA1

import (
    "encoding/hex"
    "strings"
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

func Test_pad_1_block(t *testing.T) {
    M := []byte("abc")
    _, p := parse(pad(M))

    checkWord(
        "Test_pad_1_block", p[0].Word(0), word{[]byte{0x61, 0x62, 0x63, 0x80}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(1), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(2), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(3), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(4), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(5), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(6), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(7), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(8), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(9), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(10), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(11), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(12), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(13), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(14), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_1_block", p[0].Word(15), word{[]byte{0x00, 0x00, 0x00, 0x18}}, t)
}

func Test_pad_2_blocks(t *testing.T) {
    M := []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    _, p := parse(pad(M))

    checkWord(
        "Test_pad_2_blocks", p[0].Word(0), word{[]byte{0x61, 0x62, 0x63, 0x64}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(1), word{[]byte{0x62, 0x63, 0x64, 0x65}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(2), word{[]byte{0x63, 0x64, 0x65, 0x66}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(3), word{[]byte{0x64, 0x65, 0x66, 0x67}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(4), word{[]byte{0x65, 0x66, 0x67, 0x68}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(5), word{[]byte{0x66, 0x67, 0x68, 0x69}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(6), word{[]byte{0x67, 0x68, 0x69, 0x6a}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(7), word{[]byte{0x68, 0x69, 0x6a, 0x6b}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(8), word{[]byte{0x69, 0x6a, 0x6b, 0x6c}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(9), word{[]byte{0x6a, 0x6b, 0x6c, 0x6d}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(10), word{[]byte{0x6b, 0x6c, 0x6d, 0x6e}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(11), word{[]byte{0x6c, 0x6d, 0x6e, 0x6f}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(12), word{[]byte{0x6d, 0x6e, 0x6f, 0x70}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(13), word{[]byte{0x6e, 0x6f, 0x70, 0x71}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(14), word{[]byte{0x80, 0x00, 0x00, 0x00}}, t)
    checkWord(
        "Test_pad_2_blocks", p[0].Word(15), word{[]byte{0x00, 0x00, 0x00, 0x00}}, t)
}

func Test_Digest_1_block(t *testing.T) {
    h := New("abc")
    h.Sum()

    correct := "A9993E364706816ABA3E25717850C26C9CD0D89D"
    computed := strings.ToUpper(hex.EncodeToString(h.Digest()))

    if computed != correct {
        t.Error("Test_Digest_1_block failed:  incorrect hash value!")
    }
}

func Test_Digest_2_blocks(t *testing.T) {
    h := New("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    h.Sum()

    correct := "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"
    computed := strings.ToUpper(hex.EncodeToString(h.Digest()))

    if computed != correct {
        t.Error("Test_Digest_2_blocks failed:  incorrect hash value!")
    }
}

