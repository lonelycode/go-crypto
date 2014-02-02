package Skein

import (
    "math/big"
)

// UBI chaining mode (Section 3.4)
func UBI(G, M []byte, Ts *big.Int) []byte {
    Nb := uint(len(G))
    Nm := uint(len(M))

    // TODO handle case where number of bits in M is not a mulitple of 8

    var zeroCount uint
    if Nm == 0 {
        zeroCount = Nb
    } else {
        zeroCount = (-Nm) % Nb
    }

    for zeroCount > 0 {
        M = append(M, 0x00)
        zeroCount--
    }

    k := uint(len(M)) / Nb // number of message blocks
    tf := NewThreefish(uint(Nb * 8))
    a := make([]int64, k)
    a[0] = 1
    b := make([]int64, k)
    b[k-1] = 1
    B := int64(0)
    H := G
    for i := uint(0); i < k; i++ {
        min := new(big.Int)
        if Nm < (i+1)*Nb {
            min = new(big.Int).SetInt64(int64(Nm))
        } else {
            min = new(big.Int).SetInt64(int64((i + 1) * Nb))
        }

        T := new(big.Int).Add(
            Ts,
            new(big.Int).Add(
                min,
                new(big.Int).Add(
                    new(big.Int).Mul(
                        big.NewInt(a[i]),
                        new(big.Int).Exp(
                            big.NewInt(2),
                            big.NewInt(126),
                            nil)),
                    new(big.Int).Mul(
                        big.NewInt(b[i]),
                        new(big.Int).Add(
                            new(big.Int).Mul(
                                big.NewInt(B),
                                new(big.Int).Exp(
                                    big.NewInt(2),
                                    big.NewInt(119),
                                    nil)),
                            new(big.Int).Exp(
                                big.NewInt(2),
                                big.NewInt(127),
                                nil))))))

        H = xor(tf.Encrypt(H, ToBytes(T, 16), M[i*Nb:i*Nb+Nb]), M[i*Nb:i*Nb+Nb])
    }

    return H
}

