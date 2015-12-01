package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s SUBCOMMAND\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	flag.Usage = Usage
	flag.Parse()

	if flag.NArg() < 1 {
		Usage()
		os.Exit(2)
	}

	switch flag.Arg(0) {
	case "todo":
		if flag.NArg() == 1 {
			fmt.Printf("ls todo")
			return
		}
		// Rebuid the todo item from args
		text := strings.Join(os.Args[2:], " ")
		fmt.Printf("new todo: %v", text)
	default:
		Usage()
	}
}
