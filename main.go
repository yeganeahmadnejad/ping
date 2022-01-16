package main

import (
	"fmt"
	"log"
)

func main() {
	p, err := New("google.com")
	if err != nil {
		log.Fatal(err)
	}

	r, _ := p.Run()

	for pr := range r {
		fmt.Printf("%#v\n", pr)
	}
}
