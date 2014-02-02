package SHA1

// SHA-1 words are 32-bits
type word struct {
    b []byte
}

// SHA-1 hash values are 160-bits (5 32-bit words)
type value struct {
    w []word
}

func (v *value) Bytes() []byte {
    var b []byte

    b = append(b, v.Word(0).b...)
    b = append(b, v.Word(1).b...)
    b = append(b, v.Word(2).b...)
    b = append(b, v.Word(3).b...)
    b = append(b, v.Word(4).b...)

    return b
}

func (v *value) Word(ndx int) word {
    return v.w[ndx]
}

// SHA-1 blocks are 512-bits (16 32-bit words)
type block struct {
    w []word
}

func (b *block) Word(ndx int) word {
    return b.w[ndx]
}

type Hash struct {
    M      []block
    N      int
    digest value
}

func (h *Hash) Digest() []byte {
    return h.digest.Bytes()
}

