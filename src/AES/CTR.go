package AES

import ()

type counter func([]byte) []byte
type channelData struct {
	pos  int
	data []byte
}

// Compute one block of cipher- or plainText in AES CTR mode
func computeBlock(
	src []byte, 
	ks []word, 
	blockSize int, 
	ndx int, 
	IV []byte, 
	ch chan channelData) {
		
	text := make([]byte, blockSize)
	block := cipher(IV, ks, 10)
	tmp := xor(block, src[ndx:ndx+blockSize])
	for j := range tmp {
		text[j] = tmp[j]
	}
	ch <- channelData{pos: ndx, data: text}
}

func counterMode(
	srcText []byte, 
	key []byte, 
	ctr []byte, 
	incCtr counter) ([]byte, error) {
		
	valid, err := validateInput(srcText, key, ctr, incCtr, true, "CTR")
	if !valid {
		return nil, err
	}

	destText := make([]byte, len(srcText))

	blockSize := len(key)
	blockPos := 0

	// get the key schedule
	ks := keyExpansion(key, 4, 10)

	pt := make(chan channelData)

	// launch a goroutine to compute each block of size blockSize
	for i := 0; i < len(srcText)-blockSize; i += blockSize {
		go computeBlock(srcText, ks, blockSize, blockPos, ctr, pt)

		ctr = incCtr(ctr)
		blockPos = i + blockSize
	}

	// assemble destText from the blocks received from the channel
	// (NOTE:  there will possibly be a partial block left over, which
    	//         is handled below) 
	acc := 0                         // text accumulator
	for len(srcText)-acc >= blockSize {
		output := <-pt
		for j := range output.data {
			destText[output.pos+j] = output.data[j]
		}
		acc += blockSize
	}
	//close(pt)

    	// compute the last block
	block := cipher(ctr, ks, 10)
	tmp := xor(block[:len(srcText)-blockPos], srcText[blockPos:])
	for j := 0; j < len(srcText)-blockPos; j++ {
		destText[blockPos+j] = tmp[j]
	}

	return destText, nil
}

