package base64

import (
	"encoding/base64"
	"strings"
)

func EncodeURLSafe(data []byte) string {
	var result = base64.URLEncoding.EncodeToString(data)

	return strings.TrimRight(result, "=")
}

func DecodeURLSafe(data string) ([]byte, error) {
	var pad_length = ((4 - len(data) % 4) % 4)

	data += strings.Repeat("=", pad_length)

	return base64.URLEncoding.DecodeString(data)
}
