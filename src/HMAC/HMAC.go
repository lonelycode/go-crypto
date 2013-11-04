package HMAC

import (
	"SHA1"
)

func xor(s1, s2 []byte) []byte {
	if len(s1) != len(s2) {
		panic("s1 and s2 must be the same length!")
	}
	result := make([]byte, len(s1))
	for i := 0; i < len(s1); i++ {
		result[i] = s1[i] ^ s2[i]
	}
	return result
}

func Mac_SHA1(key []byte, text string) []byte {
	var B int = 64

	ipad := make([]byte, B)
	opad := make([]byte, B)
	for i := 0; i < B; i++ {
		ipad[i] = byte(0x36)
		opad[i] = byte(0x5c)
	}

	// (1) append zeros to the end of K to create a B byte string
	pk := make([]byte, B)
	for i := 0; i < len(key); i++ {
		pk[i] = key[i]
	}

	// (2) XOR (bitwise exclusive-OR) the B byte string computed in step 1 with
	//     with ipad
	tmp := xor(pk, ipad)

	// (3) append the stream of data 'text' to the B byte string resulting from
	//     step (2)
	tmp = append(tmp, []byte(text)...)

	// (4) apply H to the stream generated in step (3)
	H := SHA1.New(string(tmp))
	H.Sum()
	h := H.Digest()

	// (5) XOR (bitwise exclusive-OR) the B byte string computed in step (1)
	//     with opad
	tmp = xor(pk, opad)

	// (6) append the H result from step (4) to the B byte string resulting from
	//     step (5)
	tmp = append(tmp, h...)

	// (7) apply H to the stream generated in step (6) and output the result
	H = SHA1.New(string(tmp))
	H.Sum()
	return H.Digest()
}
