package utils

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateSessionID generates a random session ID
//
// The generated session ID is a 32-byte (256-bit) random value, encoded as
// a URL-safe base64 string. This should be more than sufficient for most
// applications, but feel free to increase the size if you need more security.
//
// Note that the session ID is not generated using a cryptographically secure
// pseudorandom number generator (CSPRNG). If you need a CSPRNG, you should
// use a library that provides one.
func GenerateSessionID() (string, error) {
	// Generate a 32-byte (256-bit) random value
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	// Encode the bytes as a URL-safe base64 string
	return base64.URLEncoding.EncodeToString(bytes), nil
}
