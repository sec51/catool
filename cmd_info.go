package main

import (
	"fmt"
	"os"
)

var (
	allowedTypes = []string{caCmd, certCmd}
)

func printAllowedTypes(arg string) {

	if ok := contains(arg, allowedTypes); !ok {
		fmt.Println("Allowed types are:")
		for _, t := range allowedTypes {
			fmt.Println(t)
		}
		os.Exit(1)
	}
}

func contains(entry string, array []string) bool {
	for _, e := range array {
		if e == entry {
			return true
		}
	}

	return false
}
