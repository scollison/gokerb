package kerb

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"io"
)

const (
	aes128KeyLen = 128
	aes256KeyLen = 256
)

// An aesKey is an Advanced Encryption Standard (AES) key, initialized with a
// key size of 128 or 256 bits. It implements the 'key' interface. 192-bit keys
// are not supported.
type aesKey struct {
	key []byte
}

// EncryptAlgo TODO
func (c *aesKey) EncryptAlgo(usage int) int {
	if keyLenBits(c.key) == aes128KeyLen {
		return cryptAES128CtsHmacSha1_96
	}
	return cryptAES256CtsHmacSha1_96
}

// Key returns the AES key, as a slice of bytes.
func (c *aesKey) Key() []byte {
	return c.key
}

// SignAlgo returns the algorithm to use for this signature based upon the
// usage.
func (c *aesKey) SignAlgo(usage int) int {
	switch usage {
	case gssWrapSign:
		return signGssRc4Hmac
	}

	// TODO: replace with RC4-HMAC checksum algorithm. For now we are
	// using the unkeyed RSA-MD5 checksum algorithm
	return signMd5
}

var signaturekey = []byte("signaturekey\x00")

func (c *aesKey) Sign(algo, usage int, data ...[]byte) ([]byte, error) {
	if algo != signGssRc4Hmac && algo != signRc4Hmac {
		return unkeyedSign(algo, usage, data...)
	}

	h := hmac.New(sha1.New, c.key)
	h.Write(signaturekey)
	ksign := h.Sum(nil)

	chk := md5.New()
	binary.Write(chk, binary.LittleEndian, rc4HmacUsage(usage))
	for _, d := range data {
		chk.Write(d)
	}

	h = hmac.New(md5.New, ksign)
	h.Write(chk.Sum(nil))
	return h.Sum(nil), nil
}

func (c *aesKey) Encrypt(salt []byte, usage int, data ...[]byte) []byte {
	switch usage {
	case gssSequenceNumber:
		// salt is the checksum
		h := hmac.New(md5.New, c.key)
		binary.Write(h, binary.LittleEndian, uint32(0))
		h = hmac.New(md5.New, h.Sum(nil))
		h.Write(salt)
		r, _ := rc4.NewCipher(h.Sum(nil))
		for _, d := range data {
			r.XORKeyStream(d, d)
		}
		return bytes.Join(data, nil)

	case gssWrapSeal:
		// salt is the sequence number in big endian
		seqnum := binary.BigEndian.Uint32(salt)
		kcrypt := make([]byte, len(c.key))
		for i, b := range c.key {
			kcrypt[i] = b ^ 0xF0
		}
		h := hmac.New(md5.New, kcrypt)
		binary.Write(h, binary.LittleEndian, seqnum)
		r, _ := rc4.NewCipher(h.Sum(nil))
		for _, d := range data {
			r.XORKeyStream(d, d)
		}
		return bytes.Join(data, nil)
	}

	// Create the output vector, layout is 0-15 checksum, 16-23 random data, 24- actual data
	outsz := 24
	for _, d := range data {
		outsz += len(d)
	}
	out := make([]byte, outsz)
	io.ReadFull(rand.Reader, out[16:24])

	// Hash the key and usage together to get the HMAC-MD5 key
	h1 := hmac.New(md5.New, c.key)
	binary.Write(h1, binary.LittleEndian, rc4HmacUsage(usage))
	K1 := h1.Sum(nil)

	// Fill in out[:16] with the checksum
	ch := hmac.New(md5.New, K1)
	ch.Write(out[16:24])
	for _, d := range data {
		ch.Write(d)
	}
	ch.Sum(out[:0])

	// Calculate the RC4 key using the checksum
	h3 := hmac.New(md5.New, K1)
	h3.Write(out[:16])
	K3 := h3.Sum(nil)

	// Encrypt out[16:] with 16:24 being random data and 24: being the
	// encrypted data
	r, _ := rc4.NewCipher(K3)
	r.XORKeyStream(out[16:24], out[16:24])

	dst := out[24:]
	for _, d := range data {
		r.XORKeyStream(dst[:len(d)], d)
		dst = dst[len(d):]
	}

	return out
}

func (c *aesKey) Decrypt(salt []byte, algo, usage int, data []byte) ([]byte, error) {
	switch usage {
	case gssSequenceNumber:
		if algo != cryptGssRc4Hmac && algo != cryptGssNone {
			return nil, ErrProtocol
		}

		return c.Encrypt(salt, usage, data), nil

	case gssWrapSeal:
		// GSS sealing uses an external checksum for integrity and
		// since RC4 is symettric we can just reencrypt the data
		if algo != cryptGssRc4Hmac {
			return nil, ErrProtocol
		}

		return c.Encrypt(salt, usage, data), nil
	}

	if algo != cryptRc4Hmac || len(data) < 24 {
		return nil, ErrProtocol
	}

	// Hash the key and usage together to get the HMAC-MD5 key
	h1 := hmac.New(md5.New, c.key)
	binary.Write(h1, binary.LittleEndian, rc4HmacUsage(usage))
	K1 := h1.Sum(nil)

	// Calculate the RC4 key using the checksum
	h3 := hmac.New(md5.New, K1)
	h3.Write(data[:16])
	K3 := h3.Sum(nil)

	// Decrypt d.Data[16:] in place with 16:24 being random data and 24:
	// being the encrypted data
	r, _ := rc4.NewCipher(K3)
	r.XORKeyStream(data[16:], data[16:])

	// Recalculate the checksum using the decrypted data
	ch := hmac.New(md5.New, K1)
	ch.Write(data[16:])
	chk := ch.Sum(nil)

	// Check the input checksum
	if subtle.ConstantTimeCompare(chk, data[:16]) != 1 {
		return nil, ErrProtocol
	}

	return data[24:], nil
}

func keyLenBits(key []byte) int {
	return 8 * len(key)
}
