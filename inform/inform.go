// Package inform handles data encoding/decoding for the UniFi
// inform request/response cycle such that payload information
// can be successfully exchanged.
package inform

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
)

// InformContentType is the content type used for inform messages
const InformContentType string = "application/x-binary"

// ErrTruncatedPacket is returned when packet is too short
var ErrTruncatedPacket = errors.New("truncated packet")

// ErrNoMagic is returned when magic header is missing
var ErrNoMagic = errors.New("missing magic header")

// ErrUnhandledVer is returned when payload version in header
// does not match version known compatible with this library
var ErrUnhandledVer = errors.New("unhandled payload version")

// ErrNotImplemented is returned when we have not yet implemented
// functionality but know how to recognize it
var ErrNotImplemented = errors.New("functionality required is not yet implemented")

// Header represents header of inform message from Ubiquiti UniFi device
type Header struct {
	Version          uint32
	HardwareAddr     net.HardwareAddr
	flagMask         uint16
	iv               []byte
	payloadVersion   uint32
	payloadLength    uint32
	EncryptedAES     bool
	ZLibCompressed   bool
	SnappyCompressed bool
	EncryptedGCM     bool
	aad              []byte
}

// DecodePayload decodes information from a UniFi inform payload (usually json text)
// using params from Header
func (ih *Header) DecodePayload(rdr io.Reader, key string) (payload []byte, err error) {
	// sort out encryption key
	if key == "" {
		key = defaultAuthKey
	}

	k, err := hex.DecodeString(key)
	if err != nil {
		return payload, fmt.Errorf("invalid authkey %s: %w", key, err)
	}

	// decrypt
	if ih.EncryptedAES && !ih.EncryptedGCM { // not implementing CBC unless we need it
		payload, err = ih.decodeAESCBC(rdr, k)
		if err != nil {
			return payload, fmt.Errorf("AES-CBC: could not decrypt payload: %w", err)
		}
	} else if ih.EncryptedGCM {
		payload, err = ih.decodeAESGCM(rdr, k)
		if err != nil {
			return payload, fmt.Errorf("AES-GCM: could not decrypt payload: %w", err)
		}
	} else {
		return payload, ErrNotImplemented
	}

	return payload, err
}

func (ih *Header) decodeAESCBC(rdr io.Reader, key []byte) (pt []byte, err error) {
	data, err := ioutil.ReadAll(rdr)
	if err != nil {
		return pt, fmt.Errorf("could not load encrypted data: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return pt, fmt.Errorf("could not init aes block: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, ih.iv)
	mode.CryptBlocks(data, data)
	return data, nil
}

func (ih *Header) decodeAESGCM(rdr io.Reader, key []byte) (pt []byte, err error) {
	data, err := ioutil.ReadAll(rdr)
	if err != nil {
		return pt, fmt.Errorf("could not load encrypted data: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return pt, fmt.Errorf("could not init aes block: %w", err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return pt, fmt.Errorf("could not init GCM: %w", err)
	}

	pt, err = aesgcm.Open(nil, ih.iv, data, ih.aad)
	if err != nil {
		return pt, fmt.Errorf("could not decrypt payload: %w", err)
	}

	return pt, nil
}

// DecodeHeader parses a ubiquiti inform message
func DecodeHeader(rdr io.Reader) (inf Header, err error) {
	hb := make([]byte, 40, 40)
	if _, err := io.ReadFull(rdr, hb); err != nil {
		return inf, ErrTruncatedPacket
	}
	hdr := bytes.NewReader(hb)

	magic := make([]byte, 4, 4)
	binary.Read(hdr, binary.BigEndian, &magic)
	if string(magic) != magicHeader {
		return inf, ErrNoMagic
	}

	binary.Read(hdr, binary.BigEndian, &inf.Version)

	hwaddr := make([]byte, 6, 6)
	binary.Read(hdr, binary.BigEndian, &hwaddr)
	inf.HardwareAddr = hwaddr

	binary.Read(hdr, binary.BigEndian, &inf.flagMask)
	if (inf.flagMask & flagEncryptedAES) == flagEncryptedAES {
		inf.EncryptedAES = true

		if (inf.flagMask & flagEncryptedAESwithGCM) == flagEncryptedAESwithGCM {
			inf.EncryptedGCM = true
		}
	}

	if (inf.flagMask & flagZLibCompress) == flagZLibCompress {
		inf.ZLibCompressed = true
	} else if (inf.flagMask & flagSnappyCompress) == flagSnappyCompress {
		inf.SnappyCompressed = true
	}

	iv := make([]byte, 16, 16)
	binary.Read(hdr, binary.BigEndian, &iv)
	inf.iv = iv

	binary.Read(hdr, binary.BigEndian, &inf.payloadVersion)
	if inf.payloadVersion != 1 {
		return inf, ErrUnhandledVer
	}

	binary.Read(hdr, binary.BigEndian, &inf.payloadLength)

	inf.aad = hb

	return inf, nil
}
