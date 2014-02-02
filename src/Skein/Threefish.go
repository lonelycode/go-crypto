package Skein

import "math/big"

var modulus *big.Int = new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)

// Create a new instance of a Threefish cipher (Sections 3.3, 3.3.1)
func NewThreefish(Size uint) Threefish {
    tf := Threefish{}

    if Size == 256 {
        tf.Nw = 4
        tf.Nr = 72
        tf.R = [][]uint{{14, 16},
                        {52, 57},
                        {23, 40},
                        {5, 37},
                        {25, 33},
                        {46, 12},
                        {58, 22},
                        {32, 32}}
        tf.PI = []uint{0, 3, 2, 1}
    } else if Size == 512 {
        tf.Nw = 8
        tf.Nr = 72
        tf.R = [][]uint{{46, 36, 19, 37},
                        {33, 27, 14, 42},
                        {17, 49, 36, 39},
                        {44, 9, 54, 56},
                        {39, 30, 34, 24},
                        {13, 50, 10, 17},
                        {25, 29, 39, 43},
                        {8, 35, 56, 22}}
        tf.PI = []uint{2, 1, 4, 7, 6, 5, 0, 3}
    } else if Size == 1024 {
        tf.Nw = 16
        tf.Nr = 80
        tf.R = [][]uint{{24, 13, 8, 47, 8, 17, 22, 37},
                        {38, 19, 10, 55, 49, 18, 23, 52},
                        {33, 4, 51, 13, 34, 41, 59, 17},
                        {5, 20, 48, 41, 47, 28, 16, 25},
                        {41, 9, 37, 31, 12, 47, 44, 30},
                        {16, 34, 56, 51, 4, 53, 42, 41},
                        {31, 44, 47, 46, 19, 42, 44, 25},
                        {9, 48, 35, 52, 23, 31, 37, 20}}
        tf.PI = []uint{0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1}
    } else {
        panic("Size must be 256, 512, or 1024")
    }

    return tf
}

// Encryption (Section 3.3)
func (tf *Threefish) Encrypt(K, T, P []byte) []byte {
    k := BytesToWords(K)
    t := BytesToWords(T)
    p := BytesToWords(P)

    ks := tf.KeySchedule(k, t)

    v := make([]word, tf.Nw)
    for i := uint(0); i < tf.Nw; i++ {
        v[i] = p[i]
    }

    e, f := make([]word, tf.Nw), make([]word, tf.Nw)
    for d := uint(0); d < tf.Nr; d++ {
        if d%4 == 0 {
            for i := uint(0); i < tf.Nw; i++ {
                e[i] = word(new(big.Int).Mod(
                    new(big.Int).Add(
                        new(big.Int).SetUint64(uint64(v[i])),
                        new(big.Int).SetUint64(uint64(ks[d/4][i]))),
                    modulus).Uint64())
            }
        } else {
            for i := uint(0); i < tf.Nw; i++ {
                e[i] = v[i]
            }
        }

        for j := uint(0); j < tf.Nw/2; j++ {
            f[2*j], f[2*j+1] = tf.MIX(e[2*j], e[2*j+1], d, j)
        }

        for i := uint(0); i < tf.Nw; i++ {
            v[i] = f[tf.PI[i]]
        }
    }

    c := make([]word, tf.Nw)
    for i := uint(0); i < tf.Nw; i++ {
        c[i] = word(new(big.Int).Mod(
            new(big.Int).Add(
                new(big.Int).SetUint64(uint64(v[i])),
                new(big.Int).SetUint64(uint64(ks[tf.Nr/4][i]))),
            modulus).Uint64())
    }

    return WordsToBytes(c)
}

// Decryption (Section 3.3)
func (tf *Threefish) Decrypt(K, T, C []byte) []byte {
    var P []byte

    // TODO

    return P
}

// The MIX function (Section 3.3.1)
func (tf *Threefish) MIX(x0, x1 word, d, j uint) (word, word) {
    var y0, y1 word

    y0 = word(new(big.Int).Mod(
        new(big.Int).Add(
            new(big.Int).SetUint64(uint64(x0)),
            new(big.Int).SetUint64(uint64(x1))),
        modulus).Uint64())
    y1 = x1.rotl(tf.R[d%8][j]) ^ y0

    return y0, y1
}

// The key schedule (Section 3.3.2)
func (tf *Threefish) KeySchedule(k, t []word) [][]word {
    C240 := word(0x1BD11BDAA9FC1A22)

    k = append(k, C240)
    for i := uint(0); i < tf.Nw; i++ {
        k[tf.Nw] ^= k[i]
    }

    t = append(t, t[0]^t[1])

    ks := make([][]word, tf.Nr/4+1)
    for i := uint(0); i < tf.Nr/4+1; i++ {
        ks[i] = make([]word, tf.Nw)
    }

    for s := uint(0); s < tf.Nr/4+1; s++ {
        for i := uint(0); i <= tf.Nw-4; i++ {
            ks[s][i] = k[(s+i)%(tf.Nw+1)]
        }

        i := tf.Nw - 3
        ks[s][i] = word(
            new(big.Int).Mod(
                new(big.Int).Add(
                    new(big.Int).SetUint64(uint64(k[(s+i)%(tf.Nw+1)])),
                    new(big.Int).SetUint64(uint64(t[s%3]))),
                modulus).Uint64())

        i = tf.Nw - 2
        ks[s][i] = word(
            new(big.Int).Mod(
                new(big.Int).Add(
                    new(big.Int).SetUint64(uint64(k[(s+i)%(tf.Nw+1)])),
                    new(big.Int).SetUint64(uint64(t[(s+1)%3]))),
                modulus).Uint64())

        i = tf.Nw - 1
        ks[s][i] = word(
            new(big.Int).Mod(
                new(big.Int).Add(
                    new(big.Int).SetUint64(uint64(k[(s+i)%(tf.Nw+1)])),
                    new(big.Int).SetUint64(uint64(s))),
                modulus).Uint64())
    }

    return ks
}

