package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
)

func main() {
	src := []byte("あああ")
	fmt.Println("平文値", src)

	// 暗号化する
	e, err := Encrypt(src)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("暗号値", e.Cipher)

	// 復号する
	d, err := Decrypt(e.Cipher, e.Key, e.InitializationVector)
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
	// 初期化ベクトル
	InitializationVector []byte
}

func Encrypt(src []byte) (*EncryptResult, error) {
	// 暗号化の鍵を用意する
	key := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("Encrypt: failed to read rand: %w", err)
	}

	// 初期化ベクトルを用意する
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("Encrypt: failed to read rand: %w", err)
	}

	// 暗号器を用意する
	// cipher.BlockのEncryptを使うと、ECBモードで暗号化される
	// 同じデータが同じ暗号化結果になるためセキュリティ上問題がある可能性がある
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Encrypt: failed to create aes.NewCipher: %w", err)
	}

	// BlockSizeの長さになるまでパディングする
	padded := pad(src, block.BlockSize())

	fmt.Println("加工値", padded)

	// 暗号化する
	dst := make([]byte, aes.BlockSize)
	// パッと見ると良く分からないが、aes.NewCipherOnCBCModeみたいなものだと思えば良い
	stream := cipher.NewCBCEncrypter(block, iv)
	// これもメソッド名がよく分からないが、このメソッドしか持たないので暗号化を実行したと思えば良い
	stream.CryptBlocks(dst, padded)

	return &EncryptResult{
		Key:                  key,
		Cipher:               dst,
		InitializationVector: iv,
	}, nil
}

func Decrypt(src []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("desrypt: create aes.NewCipher: %w", err)
	}

	// Encryptでpaddingしているので、BlockSize以下なことはあり得ないが、
	// 万が一起きるとpanicになるのでチェックしておいた方が良さそう
	if len(src) < aes.BlockSize {
		return nil, errors.New("decrypt: ciphertext too short")
	}

	// 復号化する
	dst := make([]byte, len(src))
	stream := cipher.NewCBCDecrypter(block, iv)
	stream.CryptBlocks(dst, src)

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
	if padding > blockSize {
		return src, nil
	}
	for i := 0; i < padding; i++ {
		if src[length-1-i] != byte(padding) {
			return nil, errors.New("unpad: invalid padding")
		}
	}
	return src[:length-padding], nil
}
