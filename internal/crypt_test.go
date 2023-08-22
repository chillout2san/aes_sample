package internal_test

import (
	"sample/internal"
	"testing"
)

// Enctypt と Decrypt のテストを分けて書いても意味がないので、
// 暗号化・復号を一連でテストする
func TestCrypt(t *testing.T) {
	t.Run("暗号化と復号ができる", func(t *testing.T) {
		src := []byte("あああ")

		e, err := internal.Encrypt(src)
		if err != nil {
			t.Errorf("TestCrypt: err of Encrypt must be a nil: %v", err)
		}

		d, err := internal.Decrypt(e.Cipher, e.Key, e.InitializationVector)
		if err != nil {
			t.Errorf("TestCrypt: err of Descrypt must be a nil: %v", err)
		}

		if string(d) != "あああ" {
			t.Errorf("TestCrypt: d must be a あああ: %v", d)
		}
	})
}
