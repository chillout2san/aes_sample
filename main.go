package main

import (
	"fmt"
	"log"
	"sample/internal"
)

func main() {
	src := []byte("あああ")

	key := []byte("1234567890abcdef")

	// 暗号化する
	e, err := internal.Encrypt(src, key)
	if err != nil {
		log.Fatal(err.Error())
	}

	// 復号する
	d, err := internal.Decrypt(e.Cipher, key, e.InitializationVector)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println(string(d))
}
