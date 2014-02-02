package HMAC

import (
    "encoding/hex"
    "testing"
)

func Test_Mac_SHA1(t *testing.T) {
    key := []byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
    data := "Hi There"

    correct := "675b0b3a1b4ddf4e124872da6c2f632bfed957e9"
    computed := hex.EncodeToString(Mac_SHA1(key, data))

    if computed != correct {
        t.Error("Test_Mac_SHA1 failed:  incorrect mac!")
    }
}

