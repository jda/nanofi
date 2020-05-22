package inform

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// ErrNoMagic is returned when magic header is missing
var ErrNoMagic = errors.New("missing magic header")

// ErrUnhandledVer is returned when payload version in header
// does not match version known compatible with this library
var ErrUnhandledVer = errors.New("unhandled payload version")

// InformHeader represents header of inform message from Ubiquiti UniFi device
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
}

type Payload struct {
}

// DecodePayload decodes information from a UniFi inform payload using params from InformHeader
func (ih *Header) DecodePayload(rdr io.Reader) (inp Payload, err error) {

	return inp, err
}

// DecodeInformHeader parses a ubiquiti inform message
func DecodeHeader(rdr io.Reader) (inf Header, err error) {
	magic := make([]byte, 4, 4)
	binary.Read(rdr, binary.BigEndian, &magic)
	if string(magic) != magicHeader {
		return inf, ErrNoMagic
	}

	binary.Read(rdr, binary.BigEndian, &inf.Version)

	hwaddr := make([]byte, 6, 6)
	binary.Read(rdr, binary.BigEndian, &hwaddr)
	inf.HardwareAddr = hwaddr

	binary.Read(rdr, binary.BigEndian, &inf.flagMask)
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
	binary.Read(rdr, binary.BigEndian, &iv)
	inf.iv = iv

	binary.Read(rdr, binary.BigEndian, &inf.payloadVersion)
	if inf.payloadVersion != 1 {
		return inf, ErrUnhandledVer
	}

	binary.Read(rdr, binary.BigEndian, &inf.payloadLength)

	return inf, nil
}
