package key

import (
	"strings"
)

// String Return key as string
func (key Key) String() string { return string(key) }

// KeyParse Parse string to Key type
func KeyParse(src string) (ret Key) {
	var ok bool

	src = strings.ToLower(strings.TrimSpace(src))
	if ret, ok = keyMap[src]; !ok {
		ret = Unknown
	}

	return
}
