package Skein

import (
    "math/big"
)

// Values for the type field (Section 3.5.1)

var T_key int64 = 0  // Key (for MAC and KDF)
var T_cfg int64 = 4  // Configuration block
var T_prs int64 = 8  // Personalization string
var T_PK  int64 = 12 // Public key (for digital signature hashing)
var T_kdf int64 = 16 // Key identifier (for KDF)
var T_non int64 = 20 // Nonce (for stream cipher or randomized hashing)
var T_msg int64 = 48 // Message
var T_out int64 = 63 // Output

// The Output Function (Section 3.5.3)
func Output(G []byte, No uint) []byte {
    var O []byte

    // TODO handle case where No is not a mulitple of 8

    var count uint
    for i := 0; count < No/8; i++ {
        O = append(O, UBI(
                        G,
                        ToBytes(big.NewInt(int64(i)), 8),
                        new(big.Int).Mul(
                            big.NewInt(T_out),
                            new(big.Int).Exp(
                                big.NewInt(2),
                                big.NewInt(120),
                                nil)))...)

        count = uint(len(O))
    }

    return O
}

// Create a new instance of the simle Skein hash (Section 3.5.4)
func NewSimpleSkein(Nb, No uint) Skein {
    s := Skein{}

    if Nb != 32 && Nb != 64 && Nb != 128 {
        panic("Internal state size must be one of 32, 64, or 128")
    }

    s.Nb = Nb
    s.No = No

    // Configuration string (Section 3.5.2)
    s.C = ToBytes(big.NewInt(int64(0x33414853)), 4)
    s.C = append(s.C, ToBytes(big.NewInt(1), 2)...)
    s.C = append(s.C, ToBytes(big.NewInt(0), 2)...)
    s.C = append(s.C, ToBytes(big.NewInt(int64(No)), 8)...)
    s.C = append(s.C, 0x00) // Yl = 0
    s.C = append(s.C, 0x00) // Yf = 0
    s.C = append(s.C, 0x00) // Ym = 0
    s.C = append(s.C, ToBytes(big.NewInt(0), 13)...)

    return s
}

// Simple Hashing (Section 3.5.4)
func (s *Skein) SimpleHash(M []byte) []byte {
    Kprime := ToBytes(big.NewInt(0), s.Nb)

    Ts := new(big.Int).Mul(
        big.NewInt(T_cfg),
        new(big.Int).Exp(
            big.NewInt(2),
            big.NewInt(120),
            nil))
    G0 := UBI(Kprime, s.C, Ts)

    Ts = new(big.Int).Mul(
        big.NewInt(T_msg),
        new(big.Int).Exp(
            big.NewInt(2),
            big.NewInt(120),
            nil))
    G1 := UBI(G0, M, Ts)

    H := Output(G1, s.No)

    return H
}

