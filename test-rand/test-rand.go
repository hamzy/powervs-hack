package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func main() {
	n, err := rand.Int(rand.Reader, big.NewInt(253))
	if err != nil {
		panic(err)
	}
	subnet := n.Int64()
	fmt.Printf("%d\n", subnet)
}
