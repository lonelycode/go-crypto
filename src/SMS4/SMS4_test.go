package SMS4

import (
    "testing"
)

func checkZi(funcName string, got, expect Zi, t *testing.T) {
    for i := 0; i < 4; i++ {
        if got.b[i] != expect.b[i] {
            t.Errorf("(%s) byte %d:: expected: %02x, got: %02x\n",
                funcName, i, expect.b[i], got.b[i])
        }
    }
}

func checkBlock(funcName string, got, expect block, t *testing.T) {
    for i := 0; i < 4; i++ {
        checkZi(funcName, got.X[i], expect.X[i], t)
    }
}

func Test_rotl(t *testing.T) {
    x := Zi{[4]ZiJie{0xba, 0xad, 0xf0, 0x0d}}

    x = x.rotl(4)

    checkZi(
        "Test_rotl",
        x,
        Zi{[4]ZiJie{ZiJie(0xaa), ZiJie(0xdf), ZiJie(0x00), ZiJie(0xdb)}},
        t)
}

func Test_Encrypt_Single(t *testing.T) {
    plaintext := block{[4]Zi{Zi{[4]ZiJie{0x01, 0x23, 0x45, 0x67}},
                             Zi{[4]ZiJie{0x89, 0xab, 0xcd, 0xef}},
                             Zi{[4]ZiJie{0xfe, 0xdc, 0xba, 0x98}},
                             Zi{[4]ZiJie{0x76, 0x54, 0x32, 0x10}}}}
    MK := block{[4]Zi{Zi{[4]ZiJie{0x01, 0x23, 0x45, 0x67}},
                      Zi{[4]ZiJie{0x89, 0xab, 0xcd, 0xef}},
                      Zi{[4]ZiJie{0xfe, 0xdc, 0xba, 0x98}},
                      Zi{[4]ZiJie{0x76, 0x54, 0x32, 0x10}}}}
    
    correct := block{[4]Zi{Zi{[4]ZiJie{0x68, 0x1e, 0xdf, 0x34}},
                           Zi{[4]ZiJie{0xd2, 0x06, 0x96, 0x5e}},
                           Zi{[4]ZiJie{0x86, 0xb3, 0xe9, 0x4f}},
                           Zi{[4]ZiJie{0x53, 0x6e, 0x42, 0x46}}}}

    computed := Encrypt(plaintext, MK)

    checkBlock("Test_Encrypt_Single", computed, correct, t)
}

func Test_Encrypt_Million(t *testing.T) {
    plaintext := block{[4]Zi{Zi{[4]ZiJie{0x01, 0x23, 0x45, 0x67}},
                             Zi{[4]ZiJie{0x89, 0xab, 0xcd, 0xef}},
                             Zi{[4]ZiJie{0xfe, 0xdc, 0xba, 0x98}},
                             Zi{[4]ZiJie{0x76, 0x54, 0x32, 0x10}}}}
    MK := block{[4]Zi{Zi{[4]ZiJie{0x01, 0x23, 0x45, 0x67}},
                      Zi{[4]ZiJie{0x89, 0xab, 0xcd, 0xef}},
                      Zi{[4]ZiJie{0xfe, 0xdc, 0xba, 0x98}},
                      Zi{[4]ZiJie{0x76, 0x54, 0x32, 0x10}}}}

    correct := block{[4]Zi{Zi{[4]ZiJie{0x59, 0x52, 0x98, 0xc7}},
                           Zi{[4]ZiJie{0xc6, 0xfd, 0x27, 0x1f}},
                           Zi{[4]ZiJie{0x04, 0x02, 0xf8, 0x04}},
                           Zi{[4]ZiJie{0xc3, 0x3d, 0x3f, 0x66}}}}

    var computed block
    for i := 0; i < 1000000; i++ {
        computed = Encrypt(plaintext, MK)
        plaintext = computed
    }

    checkBlock("Test_Encrypt_Single", computed, correct, t)
}

func Test_Decrypt(t *testing.T) {
    ciphertext := block{[4]Zi{Zi{[4]ZiJie{0x68, 0x1e, 0xdf, 0x34}},
                              Zi{[4]ZiJie{0xd2, 0x06, 0x96, 0x5e}},
                              Zi{[4]ZiJie{0x86, 0xb3, 0xe9, 0x4f}},
                              Zi{[4]ZiJie{0x53, 0x6e, 0x42, 0x46}}}}
    MK := block{[4]Zi{Zi{[4]ZiJie{0x01, 0x23, 0x45, 0x67}},
                      Zi{[4]ZiJie{0x89, 0xab, 0xcd, 0xef}},
                      Zi{[4]ZiJie{0xfe, 0xdc, 0xba, 0x98}},
                      Zi{[4]ZiJie{0x76, 0x54, 0x32, 0x10}}}}

    correct := block{[4]Zi{Zi{[4]ZiJie{0x01, 0x23, 0x45, 0x67}},
                           Zi{[4]ZiJie{0x89, 0xab, 0xcd, 0xef}},
                           Zi{[4]ZiJie{0xfe, 0xdc, 0xba, 0x98}},
                           Zi{[4]ZiJie{0x76, 0x54, 0x32, 0x10}}}}

    computed := Decrypt(ciphertext, MK)

    checkBlock("Test_Decrypt", computed, correct, t)
}

