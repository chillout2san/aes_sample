package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// 暗号化された結果
type EncryptResult struct {
	// 暗号化された暗号
	Cipher []byte
	// 初期化ベクトル
	InitializationVector []byte
}

// 引数のバイト列を暗号化する
func Encrypt(plain []byte, key []byte) (*EncryptResult, error) {
	// 初期化ベクトルを用意する
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
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

	// 暗号化する
	encrypted := make([]byte, len(plain))
	// パッと見ると良く分からないが、aes.NewCipherOnCBCModeみたいなものだと思えば良い
	stream := cipher.NewCFBEncrypter(block, iv)
	// これもメソッド名がよく分からないが、このメソッドしか持たないので暗号化を実行したと思えば良い
	stream.XORKeyStream(encrypted, plain)
	return &EncryptResult{
		Cipher:               encrypted,
		InitializationVector: iv,
	}, nil
}

// 引数のバイト列を復号する
func Decrypt(src []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("desrypt: create aes.NewCipher: %w", err)
	}

	// 復号化する
	dst := make([]byte, len(src))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(dst, src)

	return dst, nil
}
