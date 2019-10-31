package bhx

import "fmt"

// Logf is alias for fmt.Printf with newline symbol at string's ending
func Logf(msg string, ctx ...interface{}) {
	fmt.Printf(msg+"\n", ctx...)
}

// Err is alias for fmt.Errorf
func Err(msg string, ctx ...interface{}) error {
	return fmt.Errorf(msg, ctx...)
}
