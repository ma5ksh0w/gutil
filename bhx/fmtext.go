package bhx

import "fmt"

// Logf is fmt.Printf alias with newline symbol at string's ending
func Logf(msg string, ctx ...interface{}) {
	fmt.Printf(msg+"\n", ctx...)
}
