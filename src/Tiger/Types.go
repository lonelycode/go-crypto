package Tiger

import (
    "encoding/binary"
)

// The 192-bit hash value
type value struct {
    a, b, c    uint64
    aa, bb, cc uint64
}

func (v *value) Bytes() []byte {
    var b []byte

    buf := make([]byte, 8)

    binary.LittleEndian.PutUint64(buf, v.a)
    b = append(b, buf...)
    binary.LittleEndian.PutUint64(buf, v.b)
    b = append(b, buf...)
    binary.LittleEndian.PutUint64(buf, v.c)
    b = append(b, buf...)

    return b
}

// Tiger blocks are 512-bits (8 64-bit words)
type block struct {
    x [8]uint64
}

type Hash struct {
    M      []block
    N      int
    digest value
}

func (h *Hash) Digest() []byte {
    return h.digest.Bytes()
}

