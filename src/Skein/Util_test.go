package Skein

import (
    "bytes"
    "math/big"
    "testing"
)

func Test_ToInt(t *testing.T) {
    b := []byte{2, 1, 1, 2, 2, 1, 1, 2}

    correct := uint64(144397771187749122)
    computed := ToInt(b)
    
    if computed != correct {
        t.Error("Test_ToInt failed - incorrect value returned!")
    }
}

func Test_ToBytes(t *testing.T) {
    var v *big.Int = big.NewInt(144397771187749122)

    correct := []byte{2, 1, 1, 2, 2, 1, 1, 2}
    computed := ToBytes(v, 8)

    if !bytes.Equal(computed, correct) {
        t.Error("Test_ToBytes failed - incorrect byte array returned!")
    }
}

func Test_BytesToWords(t *testing.T) {
    b := []byte{2, 1, 1, 2, 2, 1, 1, 2}

    correct := word(144397771187749122)
    computed := BytesToWords(b)[0]

    if computed != correct {
        t.Error("Test_BytesToWords failed - incorrect word array returned!")
    }
}

func Test_WordsToBytes(t *testing.T) {
    w := []word{word(144397771187749122)}

    correct := []byte{2, 1, 1, 2, 2, 1, 1, 2}
    computed := WordsToBytes(w)

    if !bytes.Equal(computed, correct) {
        t.Error("Test_WordsToBytes failed - incorrect byte array returned!")
    }
}
