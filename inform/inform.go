// Package inform handles data encoding/decoding for the UniFi
// inform request/response cycle such that payload information
// can be successfully exchanged.
package inform

import (
	"errors"
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
