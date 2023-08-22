package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"strings"
)

func main() {
	src := []byte(strings.Repeat("a", 16))

	// 暗号化する
	e, err := Encrypt(src)
	if err != nil {
		log.Fatal(err.Error())
	}

	// 復号する
	d, err := Decrypt(e.Cipher, e.Key)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println(string(d))
}

type EncryptResult struct {
	// 暗号化に使用した鍵
	Key []byte
	// 暗号化された暗号
	Cipher []byte
}

func Encrypt(src []byte) (*EncryptResult, error) {
	// aesの鍵は16byteらしいので固定長の配列を用意する
	key := make([]byte, 16)
	// 16byteなランダムな鍵を用意する
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("Encrypt: failed to read rand: %w", err)
	}

	// 暗号器を用意する
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Encrypt: failed to create aes.NewCipher: %w", err)
	}

	// パディングする
	src = pad(src, block.BlockSize())

	// 暗号化する
	dst := make([]byte, len(src))
	block.Encrypt(dst, src)

	return &EncryptResult{
		Key:    key,
		Cipher: dst,
	}, nil
}

func Decrypt(src []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("desrypt: create aes.NewCipher: %w", err)
	}

	if len(src) < aes.BlockSize {
		return nil, errors.New("decrypt: ciphertext too short")
	}

	dst := make([]byte, len(src))
	block.Decrypt(dst, src)

	// パディングを削除する
	result, err := unpad(dst, block.BlockSize())
	if err != nil {
		return nil, err
	}

	return result, nil
}

// パディングする
func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// パディングを削除する
func unpad(src []byte, blockSize int) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("unpad: input is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("unpad: input is not a multiple of the block size")
	}
	padding := int(src[length-1])
	if padding > blockSize || padding > length {
		return nil, errors.New("unpad: invalid padding")
	}
	for i := 0; i < padding; i++ {
		if src[length-1-i] != byte(padding) {
			return nil, errors.New("unpad: invalid padding")
		}
	}
	return src[:length-padding], nil
}
