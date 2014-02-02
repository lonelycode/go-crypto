package Skein

import (
	"bytes"
	"math/big"
	"testing"
)

func Test_ToInt(t *testing.T) {
	b := []byte{2, 1, 1, 2, 2, 1, 1, 2}

	v := ToInt(b)
	if v != 144397771187749122 {
		t.Error("Test_ToInt failed - incorrect value returned!")
	}
}

func Test_ToBytes(t *testing.T) {
	var v *big.Int = big.NewInt(144397771187749122)

	b := ToBytes(v, 8)
	if !bytes.Equal(b, []byte{2, 1, 1, 2, 2, 1, 1, 2}) {
		t.Error("Test_ToBytes failed - incorrect byte array returned!")
	}
}

func Test_BytesToWords(t *testing.T) {
	b := []byte{2, 1, 1, 2, 2, 1, 1, 2}

	w := BytesToWords(b)
	if w[0] != 144397771187749122 {
		t.Error("Test_BytesToWords failed - incorrect word array returned!")
	}
}

func Test_WordsToBytes(t *testing.T) {
	w := []word{word(144397771187749122)}

	b := WordsToBytes(w)
	if !bytes.Equal(b, []byte{2, 1, 1, 2, 2, 1, 1, 2}) {
		t.Error("Test_WordsToBytes failed - incorrect byte array returned!")
	}
}
