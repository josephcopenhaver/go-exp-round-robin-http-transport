package xascii

import (
	"bytes"
)

const (
	upperToLower = 'a' - 'A'
)

func normalize(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + upperToLower
	}

	return b
}

func EqualsIgnoreCase(s1, s2 []byte) bool {
	if len(s1) != len(s2) {
		return false
	}

	for i := range len(s1) {
		b1, b2 := s1[i], s2[i]
		if b1 == b2 {
			continue
		}

		if normalize(b1) != normalize(b2) {
			return false
		}
	}

	return true
}

func Cut(s []byte, sep []byte) ([]byte, []byte) {
	i := bytes.Index(s, sep)
	if i == -1 {
		return s, nil
	}

	return s[:i:i], s[i+1 : len(s) : len(s)]
}

func Trim(s []byte, cutset []byte) []byte {
	if len(s) == 0 || len(cutset) == 0 {
		return s[:len(s):len(s)]
	}

	for {
		if bytes.IndexByte(cutset, s[0]) == -1 {
			break
		}
		s = s[1:]
	}

	if len(s) == 0 {
		return s[:0:0]
	}

	for {
		if bytes.IndexByte(cutset, s[len(s)-1]) == -1 {
			break
		}
		s = s[:len(s)-1]
	}

	return s[:len(s):len(s)]
}
