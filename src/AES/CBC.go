package AES

// NOTE:  this code assumes that the IV, if prepended to the cipherText,
//        has been removed
func cipherBlockChainingDecrypt(
        cipherText []byte, 
        key []byte, 
        IV []byte) ([]byte, error) {
    
    valid, err := validateInput(cipherText, key, IV, nil, true, "CBC")
    if !valid {
        return nil, err
    }

    plainText := make([]byte, len(cipherText))

    blockSize := len(key)
    blockPos := 0

    // get the key schedule
    ks := invKeyExpansion(key, 4, 10)

    // first block uses the passed-in IV
    block := eqInvCipher(cipherText[blockPos:blockPos+blockSize], ks, 10)
    tmp := xor(block, IV)
    for i := range tmp {
        plainText[i] = tmp[i]
    }
    blockPos += blockSize

    // all other blocks use the previous cipherText block as the IV
    for i := blockPos; i < len(cipherText); i += blockSize {
        block = eqInvCipher(cipherText[i:i+blockSize], ks, 10)
        tmp = xor(block, cipherText[i-blockSize:i])
        for j := range tmp {
            plainText[i+j] = tmp[j]
        }
    }

    return plainText, nil
}

// NOTE:  this code assumes that the IV, if prepended to the cipherText,
//        has been removed
func cipherBlockChainingEncrypt(
    plainText []byte, 
    key []byte, 
    IV []byte) ([]byte, error) {
    
    valid, err := validateInput(plainText, key, IV, nil, false, "CBC")
    if !valid {
        return nil, err
    }

    // pad the plainText using PKCS5 padding scheme
    pad := len(key) - len(plainText) % len(key)
    paddedPlain := make([]byte, len(plainText) + pad)
    for i := range plainText {
        paddedPlain[i] = plainText[i]
    }
    for i := 0; i < pad; i++ {
        paddedPlain[len(plainText)+i] = byte(pad)
    }

    blockSize := len(key)

    // get the key schedule
    ks := keyExpansion(key, 4, 10)

    cipherText := make([]byte, len(plainText)+pad)
    for blockPos := 0; blockPos < len(cipherText); blockPos += blockSize {
        block := xor(paddedPlain[blockPos:blockPos+blockSize], IV)
        tmp := cipher(block, ks, 10)
        IV = cipherText[blockPos : blockPos+blockSize]
        for i := range tmp {
            cipherText[blockPos+i] = tmp[i]
        }
    }

    return cipherText, nil
}

