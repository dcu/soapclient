package soapclient

import (
	"encoding/hex"
	"math/rand"
)

func generateRandomData(bitSize int) []byte {
	buffer := make([]byte, bitSize)
	_attemptsToReadRandomData := 5

	for i := 0; i < _attemptsToReadRandomData; i++ {
		_, err := rand.Read(buffer)
		if err == nil {
			break
		}
	}

	return buffer
}

func generateRandomHexString(bitSize int) string {
	return hex.EncodeToString(generateRandomData(bitSize))
}

func generateID(prefix string) string {
	return prefix + "-" + generateRandomHexString(16)
}
