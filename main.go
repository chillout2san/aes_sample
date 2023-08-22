package main

import (
	"fmt"
	"log"
	"sample/internal"
)

func main() {
	src := []byte("あああ")
	fmt.Println("平文値", src)

	// 暗号化する
	e, err := internal.Encrypt(src)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("暗号値", e.Cipher)

	// 復号する
	d, err := internal.Decrypt(e.Cipher, e.Key, e.InitializationVector)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println(string(d))
}
