package soapclient

import (
	"encoding/hex"
	"math/rand"
	"sort"
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

func InOrder(keys ...string) func([]string) {
	indexes := make(map[string]int, len(keys))
	for i, k := range keys {
		indexes[k] = i
	}

	return func(input []string) {
		sort.Slice(input, func(i, j int) bool {
			return indexes[input[i]] < indexes[input[j]]
		})
	}
}
