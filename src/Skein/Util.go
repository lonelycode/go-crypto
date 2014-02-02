package Skein

import (
    "encoding/binary"
    "math/big"
)

// Exclusive-Or on an array of bytes
func xor(x1, x2 []byte) []byte {
    if len(x1) != len(x2) {
        panic("xor requires equal-length arrays")
    }

    y := make([]byte, len(x1))
    for i := 0; i < len(x1); i++ {
        y[i] = x1[i] ^ x2[i]
    }

    return y
}

// Convert a sequence of bytes to an integer (Section 3.2)
func ToInt(b []byte) uint64 {
    return binary.LittleEndian.Uint64(b)
}

// Convert an integer to a sequence of bytes (Section 3.2)
// Using big.Int for the value since the UBI chaining mode wants to pass in a
// 128-bit integer.  Man, big.Int code is ugly :-)
func ToBytes(v *big.Int, n uint) []byte {
    b := make([]byte, n)
    for i := int64(0); i < int64(n); i++ {
        aux := new(big.Int).Mod(
                    new(big.Int).Div(
                        v, 
                        new(big.Int).Exp(
                            big.NewInt(256), 
                            big.NewInt(i), 
                            nil)),
                    big.NewInt(256)).Bytes()
        if len(aux) == 0 {
            b[i] = 0x00
        } else {
            b[i] = aux[0]
        }
    }

    return b
}

// Convert a string of 8n bytes to a string of n 64-bit words (Section 3.2)
func BytesToWords(b []byte) []word {
    w := make([]word, len(b)/8)

    for i := 0; i < len(b)/8; i++ {
        w[i] = word(ToInt([]byte{b[8*i], b[8*i+1], b[8*i+2], b[8*i+3],
                                 b[8*i+4], b[8*i+5], b[8*i+6], b[8*i+7]}))
    }

    return w
}

// Convert a string of n 64-bit words to a string of 8n bytes (Section 3.2)
func WordsToBytes(w []word) []byte {
    var b []byte

    for i := 0; i < len(w); i++ {
        b = append(b, ToBytes(new(big.Int).SetUint64(uint64(w[i])), 8)...)
    }

    return b
}

