package main

import (
	"flag"
	"io"
	"os"
)

var returnCode int
var stdoutMessage string
var stderrMessage string

func main() {
	flag.IntVar(&returnCode, "return-code", 0, "返回状态码，默认为 0")
	flag.StringVar(&stdoutMessage, "stdout", "", "标准输出")
	flag.StringVar(&stderrMessage, "stderr", "", "标准错误输出")

	flag.Parse()

	if stdoutMessage != "" {
		io.WriteString(os.Stdout, stdoutMessage+"\n")
	}

	if stderrMessage != "" {
		io.WriteString(os.Stderr, stderrMessage+"\n")
	}

	os.Exit(returnCode)
}
