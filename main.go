// +build windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// pretty important address...
var amsiDLL syscall.Handle

// we like these
var functionNames = []string{
	"AmsiCloseSession",
	"AmsiInitialize",
	"AmsiOpenSession",
	"AmsiResultIsMalware",
	"AmsiScanBuffer",
	"AmsiScanString",
	"AmsiUninitialize",
}

func printProcessAddress(name string) {
	procAddr, err := syscall.GetProcAddress(amsiDLL, name)
	if err != nil {
		fmt.Errorf("Can't get", name, "process\n")
	} else {
		offset := calculateOffsetFromBaseAddress(procAddr)
		fmt.Printf("%s: 0x%X\n", name, procAddr)
		fmt.Printf("\tOffset: 0x%X (hex) | %d (decimal)\n\n", offset, offset)
	}
}

func calculateOffsetFromBaseAddress(procAddr uintptr) uintptr {
	offset := procAddr - uintptr(amsiDLL)
	return offset
}

func main() {
	fmt.Println("AMSI offset finder (x64), by Gary | @Monobehaviour / Crawl3r")

	// load amsi
	amsidll, err := syscall.LoadLibrary("amsi.dll")
	if err != nil {
		fmt.Errorf("Can't load amsi.dll into process\n\n")
		os.Exit(1)
	}
	amsiDLL = amsidll

	// find and print the function addresses and their offset from the dll base
	fmt.Println("")
	fmt.Println("Finding offsets for", len(functionNames), "dll functions")
	fmt.Println("")
	fmt.Printf("AMSI base: 0x%X\n", amsiDLL)
	fmt.Println("")

	for i := range functionNames {
		printProcessAddress(functionNames[i])
	}
}
