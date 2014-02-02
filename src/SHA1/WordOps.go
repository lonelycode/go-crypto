package SHA1

// Rotate-left (see FIPS PUB 180-4, 3.2, 5)
func rotl(x word, n uint) word {
    X := uint32(x.b[0])<<24 | uint32(x.b[1])<<16 | uint32(x.b[2])<<8 | uint32(x.b[3])
    X = (X << n) | (X >> (32 - n))

    return word{[]byte{byte((X & 0xff000000) >> 24),
                       byte((X & 0x00ff0000) >> 16),
                       byte((X & 0x0000ff00) >> 8),
                       byte(X & 0x000000ff)}}

}

// ^ (see FIPS PUB 180-4, 3.2, 1)
func and(x, y word) word {
    return word{[]byte{x.b[0] & y.b[0],
                       x.b[1] & y.b[1],
                       x.b[2] & y.b[2],
                       x.b[3] & y.b[3]}}
}

// v (see FIPS PUB 180-4, 3.2, 1)
func or(x, y word) word {
    return word{[]byte{x.b[0] | y.b[0],
                       x.b[1] | y.b[1],
                       x.b[2] | y.b[2],
                       x.b[3] | y.b[3]}}
}

// (+) (see FIPS PUB 180-4, 3.2, 1)
func xor(x, y word) word {
    return word{[]byte{x.b[0] ^ y.b[0],
                       x.b[1] ^ y.b[1],
                       x.b[2] ^ y.b[2],
                       x.b[3] ^ y.b[3]}}
}

// complement (see FIPS PUB 180-4, 3.2, 1)
func complement(x word) word {
    return word{[]byte{^x.b[0],
                       ^x.b[1],
                       ^x.b[2],
                       ^x.b[3]}}
}

// + (see FIPS PUB 180-4, 3.2, 2)
func add(x, y word) word {
    X := uint32(x.b[0])<<24 | uint32(x.b[1])<<16 | uint32(x.b[2])<<8 | uint32(x.b[3])
    Y := uint32(y.b[0])<<24 | uint32(y.b[1])<<16 | uint32(y.b[2])<<8 | uint32(y.b[3])
    Z := uint32(uint64(X+Y) % (2 << 31))
    
    return word{[]byte{byte((Z & 0xff000000) >> 24),
                       byte((Z & 0x00ff0000) >> 16),
                       byte((Z & 0x0000ff00) >> 8),
                       byte(Z & 0x000000ff)}}
}

// f (see FIPS PUB 180-4, 4.1.1)
func f(x, y, z word, t int) word {
    if t >= 0 && t <= 19 {
        return xor(and(x, y), and(complement(x), z))
    } else if t >= 20 && t <= 39 {
        return xor(x, xor(y, z))
    } else if t >= 40 && t <= 59 {
        return xor(and(x, y), xor(and(x, z), and(y, z)))
    } else if t >= 60 && t <= 79 {
        return xor(x, xor(y, z))
    }
    panic("Illegal t!")
}

