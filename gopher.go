
package gopher

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"strings"

	"github.com/vmihailenco/msgpack/v5"
)

// Profile is a JSON-extended version of AdaptixC2's
// gopher agent profile configuration.
//
// See: https://github.com/Adaptix-Framework/AdaptixC2/blob/main/Extenders/gopher_agent/src_gopher/utils/utils.go
type Profile struct {
	Type        uint     `msgpack:"type" json:"type"`
	Addresses   []string `msgpack:"addresses" json:"addresses"`
	BannerSize  int      `msgpack:"banner_size" json:"banner_size"`
	ConnTimeout int      `msgpack:"conn_timeout" json:"conn_timeout"`
	ConnCount   int      `msgpack:"conn_count" json:"conn_count"`
	UseSSL      bool     `msgpack:"use_ssl" json:"use_ssl"`
	SslCert     []byte   `msgpack:"ssl_cert" json:"ssl_cert"`
	SslKey      []byte   `msgpack:"ssl_key" json:"ssl_key"`
	CaCert      []byte   `msgpack:"ca_cert" json:"ca_cert"`
}

// Bruteforce attempts to locate and unmarshal the AdaptixC2's
// gopher Profile from the given sample.
func Bruteforce(b []byte) (*Profile, error) {
	size := aes.BlockSize + 12 + 2*aes.BlockSize

	// Brute force the configuration location
	for i := 0; i < len(b)-size; i++ {
		// Create a new AES cipher
		block, err := aes.NewCipher(b[i : i+aes.BlockSize])
		if err != nil {
			return nil, err
		}

		// Simulate GCM mode in CTR to ignore the authentication tag while brute-forcing
		iv := make([]byte, 12, 16)
		copy(iv, b[i+aes.BlockSize:i+aes.BlockSize+12])
		iv = append(iv, 0, 0, 0, 2)

		stream := cipher.NewCTR(block, iv)

		plaintext := make([]byte, 2*aes.BlockSize)
		stream.XORKeyStream(plaintext, b[i+aes.BlockSize+12:i+aes.BlockSize+12+2*aes.BlockSize])

		// Validate the probability of the configuration's location
		if !strings.Contains(string(plaintext), "type") ||
			!strings.Contains(string(plaintext), "address") {
			continue
		}

		// Brute force the configuration length
		for j := i + size; j < len(b); j++ {
			// Create a new AES cipher
			block, err = aes.NewCipher(b[i : i+aes.BlockSize])
			if err != nil {
				return nil, err
			}

			// Create the GCM cipher
			iv = b[i+aes.BlockSize : i+aes.BlockSize+12]
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}

			// Attempt to decrypt
			plaintext, err := gcm.Open(nil, iv, b[i+aes.BlockSize+12:j], nil)
			if err != nil {
				continue
			}

			var p Profile
			return &p, msgpack.Unmarshal(plaintext, &p)
		}
	}
	return nil, io.EOF
}