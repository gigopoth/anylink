package utils

// BytesToString converts byte slice to string without unsafe pointer operations (CWE-248).
func BytesToString(b []byte) string {
	return string(b)
}

// StringToBytes converts string to byte slice without unsafe pointer operations (CWE-248).
func StringToBytes(s string) []byte {
	return []byte(s)
}
