package Tiger

import (
	"encoding/hex"
	"strings"
	"testing"
)

func Test_Digest_43bytes(t *testing.T) {
	h := New("The quick brown fox jumps over the lazy dog")
	h.Sum()

	correct := strings.ToUpper("6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075")
	result := strings.ToUpper(hex.EncodeToString(h.Digest()))
	if result != correct {
		t.Error("Test_Digest_43bytes failed:  incorrect hash value!")
	}
}

func Test_Digest_28bytes(t *testing.T) {
	h := New("Test vector from febooti.com")
	h.Sum()

	correct := strings.ToUpper("382599758b759db703d4940c08c3393182adad7e9a7e590f")
	result := strings.ToUpper(hex.EncodeToString(h.Digest()))
	if result != correct {
		t.Error("Test_Digest_28bytes failed:  incorrect hash value!")
	}
}

func Test_Digest_0bytes(t *testing.T) {
	h := New("")
	h.Sum()

	correct := strings.ToUpper("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3")
	result := strings.ToUpper(hex.EncodeToString(h.Digest()))
	if result != correct {
		t.Error("Test_Digest_0bytes failed:  incorrect hash value!")
	}
}

func Test_Digest_3bytes(t *testing.T) {
	h := New("abc")
	h.Sum()

	correct := strings.ToUpper("2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93")
	result := strings.ToUpper(hex.EncodeToString(h.Digest()))
	if result != correct {
		t.Error("Test_Digest_0bytes failed:  incorrect hash value!")
	}
}

func Test_Digest_80bytes(t *testing.T) {
	h := New("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
	h.Sum()

	correct := strings.ToUpper("1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd")
	result := strings.ToUpper(hex.EncodeToString(h.Digest()))
	if result != correct {
		t.Error("Test_Digest_0bytes failed:  incorrect hash value!")
	}
}

func Test_Digest_125bytes(t *testing.T) {
	h := New("Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.")
	h.Sum()

	correct := strings.ToUpper("631ABDD103EB9A3D245B6DFD4D77B257FC7439501D1568DD")
	result := strings.ToUpper(hex.EncodeToString(h.Digest()))
	if result != correct {
		t.Error("Test_Digest_0bytes failed:  incorrect hash value!")
	}
}
