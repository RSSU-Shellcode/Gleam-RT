package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	dumpASMx86()
	dumpASMx64()
}

func dumpASMx86() {
	bin, err := os.ReadFile("dist/GleamRT_x86.bin")
	checkError(err)
	mod := dumpBytesHex(bin)

	err = os.WriteFile("dist/GleamRT_x86.inst", mod, 0600)
	checkError(err)

	builder := bytes.Buffer{}
	builder.WriteString(".model flat\r\n")
	builder.WriteString("\r\n")
	builder.WriteString(".code\r\n")
	builder.WriteString("\r\n")
	builder.WriteString("_InitRuntime@4 proc\r\n")
	builder.Write(mod)
	builder.WriteString("_InitRuntime@4 endp\r\n")
	builder.WriteString("\r\n")
	builder.WriteString("end\r\n")

	mod = builder.Bytes()
	err = os.WriteFile("dist/GleamRT_x86.asm", mod, 0600)
	checkError(err)
}

func dumpASMx64() {
	bin, err := os.ReadFile("dist/GleamRT_x64.bin")
	checkError(err)
	mod := dumpBytesHex(bin)

	err = os.WriteFile("dist/GleamRT_x64.inst", mod, 0600)
	checkError(err)

	builder := bytes.Buffer{}
	builder.WriteString(".code\r\n")
	builder.WriteString("\r\n")
	builder.WriteString("InitRuntime proc\r\n")
	builder.Write(mod)
	builder.WriteString("InitRuntime endp\r\n")
	builder.WriteString("\r\n")
	builder.WriteString("end\r\n")

	mod = builder.Bytes()
	err = os.WriteFile("dist/GleamRT_x64.asm", mod, 0600)
	checkError(err)
}

func dumpBytesHex(b []byte) []byte {
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
		if counter != 16 {
			builder.WriteString(", ")
			continue
		}
		counter = 0
		builder.WriteString("\r\n")
	}
	return builder.Bytes()
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
