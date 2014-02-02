package AES

import (
    "errors"
)

func validateInput(
        text []byte, 
        key []byte, 
        IV []byte, 
        incCtr counter, 
        decrypting bool, 
        mode string) (bool, error) {
    
    if text == nil || len(text) == 0 {
        if decrypting {
            return false, errors.New("must supply a ciphertext!")
        } else {
            return false, errors.New("must supply a plaintext!")
        }
    }

    if key == nil || len(key) == 0 {
        return false, errors.New("must supply a valid key!")
    }

    if IV == nil || len(IV) == 0 {
        return false, errors.New("must supply a valid IV!")
    }

    if len(key) != len(IV) {
        return false, errors.New("key length must equal IV length!")
    }

    if decrypting && mode == "CBC" {
        if len(text)%len(key) != 0 {
            return false, errors.New("ciphertext must be a " +
                "multiple of key length!")
        }
    }

    if mode == "CTR" {
        if incCtr == nil {
            return false, errors.New("must supply a valid " +
                "function to increment the counter!")
        }
    }

    return true, nil
}

