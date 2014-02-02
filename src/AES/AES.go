package AES

import (
    "crypto/rand"
    "errors"
    "fmt"
    "io"
    "strings"
)

// S-box matrix (see Sec. 5.1.1, Fig. 7 of FIPS 197)
var SBOX [16][16]byte = [16][16]byte{
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 
     0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 
     0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 
     0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 
     0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 
     0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 
     0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
     0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 
     0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 
     0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 
     0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 
     0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 
     0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 
     0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 
     0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 
     0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 
     0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
}

// Inverse S-box matrix (see Sec. 5.3.2, Fig. 14 of FIPS 197)
var SBOXINV [16][16]byte = [16][16]byte{
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 
     0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 
     0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 
     0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 
     0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 
     0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 
     0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 
     0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 
     0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 
     0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 
     0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 
     0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 
     0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 
     0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 
     0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 
     0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 
     0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
}

// round constant word array (see Sec. 5.2 of FIPS 197)
var RCON [15]word = [15]word{
    // RCON index is 1-based, so need a dummy row at the beginning
    word{b: [4]byte{0xff, 0xff, 0xff, 0xff}},
    word{b: [4]byte{0x01, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x02, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x04, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x08, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x10, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x20, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x40, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x80, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x1b, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x36, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x6c, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0xd8, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0xa6, 0x00, 0x00, 0x00}},
    word{b: [4]byte{0x4d, 0x00, 0x00, 0x00}},
}

const Nb = 4

// AES words are four bytes, not the usual two bytes
type word struct {
    b [4]byte
}

type state struct {
    b [4][Nb]byte
}

// print the state in a pretty format
func (s state) dumpState(msg string, oneLine bool) {
    if oneLine {
        fmt.Print(msg + ": ")
        for i := 0; i < 4; i++ {
            for j := 0; j < Nb; j++ {
                fmt.Printf("%02x", s.b[j][i])
            }
        }
        fmt.Println()
    } else {
        fmt.Println("------------------")
        fmt.Println(msg)
        for i := 0; i < 4; i++ {
            for j := 0; j < Nb; j++ {
                fmt.Printf(" %2x ", s.b[i][j])
            }
            fmt.Println()
        }
        fmt.Println("------------------")
    }
}

// print a given round of the key schedule in a pretty format
func dumpKeySchedule(w []word, round int) {
    fmt.Print("ik_sch: ")
    for i := 0; i < 4; i++ {
        for j := 0; j < Nb; j++ {
            fmt.Printf("%02x", w[round*Nb+i].b[j])
        }
    }
    fmt.Println()
}

// Take an input word and apply the S-Box to each of the four bytes to produce
// an output word
func (w word) subWord() word {
    var result word

    for i := 0; i < 4; i++ {
        x := w.b[i] >> 4  // row of the S-box matrix is high 4 bits
        y := w.b[i] & 0xf // column of the S-box matrix is low 4 bits
        
        result.b[i] = SBOX[x][y]
    }

    return result
}

// Take an input word [a0,a1,a2,a3] and perform a cyclic permutation to
// produce the output word [a1,a2,a3,a0]
func (w word) rotWord() word {
    var result word

    for i := 0; i < 4; i++ {
        result.b[i] = w.b[(i+1)%4]
    }

    return result
}

// Exlusive-OR function for AES words
func (w1 word) xor(w2 word) word {
    var result word

    for i := 0; i < 4; i++ {
        result.b[i] = w1.b[i] ^ w2.b[i]
    }

    return result
}

// Exclusive-OR function for regular bytes
func xor(b1, b2 []byte) []byte {
    result := make([]byte, len(b1))

    for i := 0; i < len(b1); i++ {
        result[i] = b1[i] ^ b2[i]
    }

    return result
}

// Galois Field (256-byte) multiplication of two bytes
// (adapted from http://en.wikipedia.org/wiki/Rijndael_mix_columns)
func galoisMult(a, b byte) byte {
    var p byte

    p = 0
    for i := 0; i < 8; i++ {
        if b&1 != 0 {
            p ^= a
        }
        hiBitSet := a & 0x80
        a <<= 1
        if hiBitSet != 0 {
            a ^= 0x1b // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1
    }

    return p
}

// Takes a Cipher Key as a byte array and generates a key schedule
// (see Sec. 5.2 of FIPS 197)
func keyExpansion(key []byte, Nk, Nr int) []word {
    w := make([]word, Nb*(Nr+1))

    for i := 0; i < Nk; i++ {
        w[i] = word{[4]byte{key[4*i],
                            key[4*i+1],
                            key[4*i+2],
                            key[4*i+3]}}
    }

    for i := Nk; i < Nb*(Nr+1); i++ {
        temp := w[i-1]
        if i%Nk == 0 {
            temp = temp.rotWord().subWord().xor(RCON[i/Nk])
        } else if Nk > 6 && i%Nk == 4 {
            temp = temp.subWord()
        }
        w[i] = w[i-Nk].xor(temp)
    }

    return w
}

// When using the "equivalent inverse cipher", there is an extra step
// in the key expansion
// (see Sec. 5.3.5, Figure 15 in FIPS 197)
func invKeyExpansion(key []byte, Nk, Nr int) []word {
    dw := keyExpansion(key, Nk, Nr)

    w := make([]word, (Nr+1)*Nb)
    for i := 0; i < (Nr+1)*Nb; i++ {
        w[i] = dw[i]
    }

    for round := 1; round < Nr; round++ {
        invMixColumns(dw, w, round)
    }

    return dw
}

// non-linear byte substitution that operates independently on each byte of
// the State using a substitution table (S-box)
// (see Sec. 5.1.1 of FIPS 197)
func (s state) subBytes() state {
    var result state

    for i := 0; i < 4; i++ {
        for j := 0; j < 4; j++ {
            x := s.b[i][j] >> 4  // row is high 4 bits
            y := s.b[i][j] & 0xf // column is low 4 bits
            
            result.b[i][j] = SBOX[x][y]
        }
    }

    return result
}

// inverse of the subBytes() method used in the cipher
// (see Sec. 5.3.2 of FIPS 197)
func (s state) invSubBytes() state {
    var result state

    for i := 0; i < 4; i++ {
        for j := 0; j < 4; j++ {
            x := s.b[i][j] >> 4  // row is high 4 bits
            y := s.b[i][j] & 0xf // column is low 4 bits
           
            result.b[i][j] = SBOXINV[x][y]
        }
    }

    return result
}

// the bytes in the last three rows of the State are cyclically shifted over
// different numbers of bytes (offsets).  The first row, r = 0, is not shifted.
// (see Sec. 5.1.2 of FIPS 197)
func (s state) shiftRows() state {
    var result state

    for i := 0; i < 4; i++ {
        for j := 0; j < Nb; j++ {
            result.b[i][j] = s.b[i][(i+j)%4]
        }
    }

    return result
}

// inverse of the shiftRows() method used in the cipher
// (see Sec. 5.3.1 of FIPS 197)
func (s state) invShiftRows() state {
    var result state

    for i := 0; i < 4; i++ {
        for j := 0; j < Nb; j++ {
            result.b[i][(i+j)%4] = s.b[i][j]
        }
    }

    return result
}

// operates on the State column-by-column, treating each column as a four-term
// polynomial
// (see Sec. 5.1.3 of FIPS 197)
// (adapted from http://en.wikipedia.org/wiki/Rijndael_mix_columns)
func (s state) mixColumns() state {
    var result state

    for i := 0; i < 4; i++ {
        result.b[0][i] = galoisMult(0x02, s.b[0][i]) ^
                         galoisMult(0x03, s.b[1][i]) ^
                         s.b[2][i]                   ^
                         s.b[3][i]
        result.b[1][i] = s.b[0][i]                   ^
                         galoisMult(0x02, s.b[1][i]) ^
                         galoisMult(0x03, s.b[2][i]) ^
                         s.b[3][i]
        result.b[2][i] = s.b[0][i]                   ^
                         s.b[1][i]                   ^
                         galoisMult(0x02, s.b[2][i]) ^
                         galoisMult(0x03, s.b[3][i])
        result.b[3][i] = galoisMult(0x03, s.b[0][i]) ^
                         s.b[1][i]                   ^
                         s.b[2][i]                   ^
                         galoisMult(0x02, s.b[3][i])
    }

    return result
}

// inverse of the mixColumns() method used in the cipher
// (see Sec. 5.3.3 in FIPS 197)
func (s state) invMixColumns() state {
    var result state

    for i := 0; i < 4; i++ {
        result.b[0][i] = galoisMult(0x0e, s.b[0][i]) ^
                         galoisMult(0x0b, s.b[1][i]) ^
                         galoisMult(0x0d, s.b[2][i]) ^
                         galoisMult(0x09, s.b[3][i])
        result.b[1][i] = galoisMult(0x09, s.b[0][i]) ^
                         galoisMult(0x0e, s.b[1][i]) ^
                         galoisMult(0x0b, s.b[2][i]) ^
                         galoisMult(0x0d, s.b[3][i])
        result.b[2][i] = galoisMult(0x0d, s.b[0][i]) ^
                         galoisMult(0x09, s.b[1][i]) ^
                         galoisMult(0x0e, s.b[2][i]) ^
                         galoisMult(0x0b, s.b[3][i])
        result.b[3][i] = galoisMult(0x0b, s.b[0][i]) ^
                         galoisMult(0x0d, s.b[1][i]) ^
                         galoisMult(0x09, s.b[2][i]) ^
                         galoisMult(0x0e, s.b[3][i])
    }

    return result
}

// inverse of the mixColumns() method used in the cipher, applied to a word array
// (see Sec. 5.3.3 in FIPS 197)
func invMixColumns(dw []word, w []word, round int) {
    for i := 0; i < 4; i++ {
        dw[round*Nb+i].b[0] = galoisMult(0x0e, w[round*Nb+i].b[0]) ^
                              galoisMult(0x0b, w[round*Nb+i].b[1]) ^
                              galoisMult(0x0d, w[round*Nb+i].b[2]) ^
                              galoisMult(0x09, w[round*Nb+i].b[3])
        dw[round*Nb+i].b[1] = galoisMult(0x09, w[round*Nb+i].b[0]) ^
                              galoisMult(0x0e, w[round*Nb+i].b[1]) ^
                              galoisMult(0x0b, w[round*Nb+i].b[2]) ^
                              galoisMult(0x0d, w[round*Nb+i].b[3])
        dw[round*Nb+i].b[2] = galoisMult(0x0d, w[round*Nb+i].b[0]) ^
                              galoisMult(0x09, w[round*Nb+i].b[1]) ^
                              galoisMult(0x0e, w[round*Nb+i].b[2]) ^
                              galoisMult(0x0b, w[round*Nb+i].b[3])
        dw[round*Nb+i].b[3] = galoisMult(0x0b, w[round*Nb+i].b[0]) ^
                              galoisMult(0x0d, w[round*Nb+i].b[1]) ^
                              galoisMult(0x09, w[round*Nb+i].b[2]) ^
                              galoisMult(0x0e, w[round*Nb+i].b[3])
    }
}

// Round Key is added to the State by a simple bitwise XOR operation
// (see Sec. 5.1.4 of FIPS 197)
func (s state) addRoundKey(w []word, round int) state {
    var result state

    for i := 0; i < 4; i++ {
        for j := 0; j < Nb; j++ {
            result.b[i][j] = s.b[i][j] ^ w[round*Nb+j].b[i]
        }
    }

    return result
}

// the cipher routine
// (see Sec. 5.1 of FIPS 197)
func cipher(in []byte, w []word, Nr int) []byte {
    var s state

    // copy the input to the state (see Sec. 3.4 of FIPS 197)
    for i := 0; i < 4; i++ {
        for j := 0; j < Nb; j++ {
            s.b[i][j] = in[i+4*j]
        }
    }

    s = s.addRoundKey(w, 0)

    // First Nr-1 rounds employ all transformations
    for round := 1; round < Nr; round++ {
        s = s.subBytes()
        s = s.shiftRows()
        s = s.mixColumns()
        s = s.addRoundKey(w, round)
    }

    // Final round does not include MixColumns()
    s = s.subBytes()
    s = s.shiftRows()
    s = s.addRoundKey(w, Nr)

    // copy the state to the output (see Sec. 3.4 of FIPS 197)
    out := make([]byte, 4*Nb)
    for i := 0; i < 4; i++ {
        for j := 0; j < Nb; j++ {
            out[i+4*j] = s.b[i][j]
        }
    }

    return out
}

func invCipher(in []byte, w []word, Nr int) []byte {
    var s state

    // copy the input to the state (see Sec. 3.4 of FIPS 197)
    for i := 0; i < 4; i++ {
        for j := 0; j < Nb; j++ {
            s.b[i][j] = in[i+4*j]
        }
    }

    s = s.addRoundKey(w, Nr)

    // First Nr-1 rounds employ all transformations
    for round := Nr - 1; round > 0; round-- {
        s = s.invShiftRows()
        s = s.invSubBytes()
        s = s.addRoundKey(w, round)
        s = s.invMixColumns()
    }

    // Final round does not include invMixColumns()
    s = s.invShiftRows()
    s = s.invSubBytes()
    s = s.addRoundKey(w, 0)

    // copy the state to the output (see Sec. 3.4 of FIPS 197)
    out := make([]byte, 4*Nb)
    for i := 0; i < 4; i++ {
        for j := 0; j < Nb; j++ {
            out[i+4*j] = s.b[i][j]
        }
    }

    return out
}

// the Equivalent Inverse Cipher
// (see Sec. 5.3.5 of FIPS 197)
func eqInvCipher(in []byte, dw []word, Nr int) []byte {
    var s state

    // copy the input to the state (see Sec. 3.4 of FIPS 197)
    for i := 0; i < 4; i++ {
        for j := 0; j < Nb; j++ {
            s.b[i][j] = in[i+4*j]
        }
    }

    s = s.addRoundKey(dw, Nr)

    // First Nr-1 rounds employ all transformations
    for round := Nr - 1; round > 0; round-- {
        s = s.invSubBytes()
        s = s.invShiftRows()
        s = s.invMixColumns()
        s = s.addRoundKey(dw, round)
    }

    // Final round does not include invMixColumns()
    s = s.invSubBytes()
    s = s.invShiftRows()
    s = s.addRoundKey(dw, 0)

    // copy the state to the output (see Sec. 3.4 of FIPS 197)
    out := make([]byte, 4*Nb)
    for i := 0; i < 4; i++ {
        for j := 0; j < Nb; j++ {
            out[i+4*j] = s.b[i][j]
        }
    }

    return out
}

func GenerateKey(keyLen int) ([]byte, error) {
    key := make([]byte, keyLen)
    n, err := io.ReadFull(rand.Reader, key)
    if n != keyLen || err != nil {
        return nil, errors.New("error generating key!")
    }
    return key, nil
}

func Encrypt(
    plain string,
    key []byte,
    ctr counter,
    mode string) ([]byte, []byte, error) {

    // generate a random IV
    IV := make([]byte, len(key))
    n, err := io.ReadFull(rand.Reader, IV)
    if n != len(IV) || err != nil {
        return nil, nil, err
    }

    if strings.ToUpper(mode) == "CTR" {
        cipher, err := counterMode(
                            []byte(plain),
                            key,
                            IV,
                            ctr)
        
        return cipher, IV, err
    } else if strings.ToUpper(mode) == "CBC" {
        cipher, err := cipherBlockChainingEncrypt(
                            []byte(plain),
                            key,
                            IV)
 
        return cipher, IV, err
    }

    return nil, nil, errors.New("Unknown mode!")
}

func Decrypt(
    cipher []byte,
    key []byte,
    IV []byte,
    ctr counter,
    mode string) ([]byte, error) {

    if strings.ToUpper(mode) == "CTR" {
        plain, err := counterMode(
                            cipher,
                            key,
                            IV,
                            ctr)

        return plain, err
    } else if strings.ToUpper(mode) == "CBC" {
        plain, err := cipherBlockChainingDecrypt(
                            cipher,
                            key,
                            IV)

        return plain, err
    }

    return nil, errors.New("Unknown mode!")
}

