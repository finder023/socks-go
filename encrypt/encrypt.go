package encrypt

import "math/bits"

const XOR_KEY uint8 = 0b10110010

type Encryptor struct {
	XorKey uint8
}

func (e *Encryptor) Encrypt(data []byte) {
	for i := range data {
		data[i] = bits.RotateLeft8(data[i], 3)
		data[i] = bits.Reverse8(data[i])
		data[i] ^= e.XorKey
	}
}

func (e *Encryptor) Decrypt(data []byte) {
	for i := range data {
		data[i] ^= e.XorKey
		data[i] = bits.Reverse8(data[i])
		data[i] = bits.RotateLeft8(data[i], -3)
	}
}

func (e *Encryptor) NaiveEncrypt(data []byte) {
	for i := range data {
		data[i] = bits.RotateLeft8(data[i], 3)
		data[i] = bits.Reverse8(data[i])
		data[i] ^= XOR_KEY
	}
}

func (e *Encryptor) NaiveDecrypt(data []byte) {
	for i := range data {
		data[i] ^= XOR_KEY
		data[i] = bits.Reverse8(data[i])
		data[i] = bits.RotateLeft8(data[i], -3)
	}
}
