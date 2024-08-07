package coder

import (
	"crypto/aes"

	"golang.org/x/text/encoding/charmap"
)

var (
	remainLow       byte = 15
	remainUp        byte = 240
	upperBitAdd0100 byte = 64
	upperBitAdd0101 byte = 80

	key = []byte{235, 144, 90, 188, 5, 44, 85, 170, 235, 144, 90, 188, 5, 44, 85, 170}
)

func getTransferDecryptString(data string) ([]byte, error) {
	encoder := charmap.ISO8859_1.NewEncoder()
	out, err := encoder.Bytes([]byte(data))
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(out)/2)

	for i := 0; i < len(out); i += 2 {
		b1 := out[i] & remainLow
		b1 <<= 4
		b1 &= remainUp

		b2 := out[i+1] & remainLow
		b2 |= b1

		result[i/2] = b2
	}

	return result, nil
}

func getTransferEncrptString(data []byte) (string, error) {
	result := make([]byte, len(data)*2)
	for i := 0; i < len(data); i++ {
		b1 := data[i] >> 4
		b1 = b1 & remainLow
		if b1 == 0 {
			b1 |= upperBitAdd0101
		} else {
			b1 |= upperBitAdd0100
		}

		b2 := data[i] & remainLow
		if b2 == 0 {
			b2 |= upperBitAdd0101
		} else {
			b2 |= upperBitAdd0100
		}

		result[i*2] = b1
		result[i*2+1] = b2
	}

	decoder := charmap.ISO8859_1.NewDecoder()
	out, err := decoder.Bytes(result)
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func Decrypt(encryptedData string) (string, error) {
	data, err := getTransferDecryptString(encryptedData)
	if err != nil {
		panic(err)
	}

	blockSize := 16
	var result []byte
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockDec := make([]byte, blockSize)

	// 成块的
	remain := 0
	for i := 0; i+blockSize < len(data); i += blockSize {
		c.Decrypt(blockDec, data[i:i+blockSize])
		result = append(result, blockDec...)
		remain = i + blockSize
	}
	// 不成块的
	if remain != len(data) {
		for i := remain; i < len(data); i += 1 {
			result = append(result, byte(data[i]^byte(i-remain)))
		}

	}

	return string(result), nil
}

func Encrypt(decryptedData string) (string, error) {
	data := []byte(decryptedData)
	blockSize := 16
	var result []byte
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockEnc := make([]byte, blockSize)

	// 成块的
	remain := 0
	for i := 0; i+blockSize < len(data); i += blockSize {
		c.Encrypt(blockEnc, data[i:i+blockSize])
		result = append(result, blockEnc...)
		remain = i + blockSize
	}

	// 不成块的
	if remain != len(data) {
		for i := remain; i < len(data); i += 1 {
			result = append(result, byte(data[i]^byte(i-remain)))
		}
	}
	return getTransferEncrptString(result)
}
