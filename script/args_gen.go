package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/RSSU-Shellcode/GRT-Config/argument"
)

func main() {
	arg0 := &argument.Arg{
		ID:   0,
		Data: []byte{0x78, 0x56, 0x34, 0x12},
	}
	arg1 := &argument.Arg{
		ID:   1,
		Data: []byte("aaaabbbbccc\x00"),
	}
	arg2 := &argument.Arg{
		ID:   2,
		Data: make([]byte, 0),
	}
	stub, err := argument.Encode(arg0, arg1, arg2)
	checkError(err)

	fmt.Println(dumpBytesHex(stub))
}

func dumpBytesHex(b []byte) string {
	n := len(b)
	builder := bytes.Buffer{}
	builder.Grow(len("0FFh, ")*n - len(", "))
	buf := make([]byte, 2)
	var counter = 0
	for i := 0; i < n; i++ {
		if counter == 0 {
			builder.WriteString("  db ")
		}
		hex.Encode(buf, b[i:i+1])
		builder.WriteString("0")
		builder.Write(bytes.ToUpper(buf))
		builder.WriteString("h")
		if i == n-1 {
			builder.WriteString("\r\n")
			break
		}
		counter++
		if counter != 4 {
			builder.WriteString(", ")
			continue
		}
		counter = 0
		builder.WriteString("\r\n")
	}
	return builder.String()
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
