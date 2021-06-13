package encrypt

import "math/bits"

const XOR_KEY uint8 = 0b10110010

func Encrypt(data []byte) {
	for i := range data {
		data[i] = bits.RotateLeft8(data[i], 3)
		data[i] = bits.Reverse8(data[i])
		data[i] ^= XOR_KEY
	}
}

func Decrypt(data []byte) {
	for i := range data {
		data[i] ^= XOR_KEY
		data[i] = bits.Reverse8(data[i])
		data[i] = bits.RotateLeft8(data[i], -3)
	}
}
