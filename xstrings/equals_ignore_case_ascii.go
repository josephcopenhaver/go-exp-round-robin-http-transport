package xstrings

const (
	upperToLower = 'a' - 'A'
)

func EqualsIgnoreCaseASCII(s1, s2 string) bool {
	if len(s1) != len(s2) {
		return false
	}

	for i := range len(s1) {
		b1, b2 := s1[i], s2[i]
		if b1 == b2 {
			continue
		}

		if b1 >= 'A' && b1 <= 'Z' {
			b1 += upperToLower
		}
		if b2 >= 'A' && b2 <= 'Z' {
			b2 += upperToLower
		}

		if b1 != b2 {
			return false
		}
	}

	return true
}
