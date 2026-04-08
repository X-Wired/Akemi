// Mutations.go
package fuzz

import (
	"net/url"
)

// BitFlipMutations generates mutated payloads by flipping each bit in the original payload.
func BitFlipMutations(payload string) []string {
	var mutations []string
	bytesPayload := []byte(payload)
	// Iterate over each byte in the payload.
	for i := 0; i < len(bytesPayload); i++ {
		// Flip each of the 8 bits of the current byte.
		for bit := 0; bit < 8; bit++ {
			mutated := make([]byte, len(bytesPayload))
			copy(mutated, bytesPayload)
			mutated[i] ^= 1 << bit // Flip the bit at the current position.
			mutations = append(mutations, string(mutated))
		}
	}
	return mutations
}

// URLEncodingMutations returns URL encoded and double URL encoded versions of the payload.
func URLEncodingMutations(payload string) []string {
	var mutations []string
	encoded := url.QueryEscape(payload)
	doubleEncoded := url.QueryEscape(encoded)
	mutations = append(mutations, encoded, doubleEncoded)
	return mutations
}

// MutatePayload aggregates both bit-flip and URL encoding mutations, returning a unique set of mutated payloads.
func MutatePayload(payload string) []string {
	mutationSet := make(map[string]bool)
	// Include the original payload.
	mutationSet[payload] = true

	// Add bit-flip mutations.
	for _, mutation := range BitFlipMutations(payload) {
		mutationSet[mutation] = true
	}

	// Add URL encoding mutations.
	for _, mutation := range URLEncodingMutations(payload) {
		mutationSet[mutation] = true
	}

	// Convert the set into a slice.
	var mutations []string
	for m := range mutationSet {
		mutations = append(mutations, m)
	}
	return mutations
}
