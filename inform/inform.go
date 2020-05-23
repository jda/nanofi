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

// Payload is the payload, yo
type Payload struct {
	plaintext []byte
}

// DecodePayload decodes information from a UniFi inform payload using params from InformHeader
func (ih *Header) DecodePayload(rdr io.Reader, key string) (inp Payload, err error) {
	// sort out encryption key
	if key == "" {
		key = defaultAuthKey
	}

	k, err := hex.DecodeString(key)
	if err != nil {
		return inp, fmt.Errorf("invalid authkey %s: %w", key, err)
	}

	// decrypt
	if ih.EncryptedAES && !ih.EncryptedGCM { // not implementing CBC unless we need it
		return inp, ErrNotImplemented
	} else if ih.EncryptedGCM {
		inp.plaintext, err = ih.decodeAESCBC(rdr, k)
		if err == nil {
			return inp, fmt.Errorf("could not decrypt payload: %w", err)
		}
	} else {
		return inp, ErrNotImplemented
	}

	return inp, err
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

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return pt, fmt.Errorf("could not init GCM: %w", err)
	}

	//return pt, fmt.Errorf("len of data: %+v, payload len from header: %+v", len(data), ih.payloadLength)
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
