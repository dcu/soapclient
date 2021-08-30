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

func eachSortedKeyValue(m map[string]interface{}, cb func(key string, value interface{})) {
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		cb(k, m[k])
	}
}
