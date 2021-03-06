package inform

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test case for inform packet using AES GCM without compression

var sampleAdopt = []byte{
	0x54, 0x4e, 0x42, 0x55, 0x00, 0x00, 0x00, 0x00,
	0x74, 0x83, 0xc2, 0x0f, 0x15, 0xb0, 0x00, 0x01,
	0xe4, 0xa5, 0x12, 0xef, 0x15, 0x4e, 0x75, 0x7f,
	0x65, 0x5c, 0x7f, 0x43, 0x1b, 0x80, 0x16, 0xd5,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x80,
	0xc0, 0x34, 0xc0, 0x9b, 0x68, 0xbc, 0xb8, 0x13,
	0x39, 0x4c, 0x0f, 0x10, 0x81, 0x8b, 0x5a, 0x5c,
	0xff, 0x07, 0x26, 0xac, 0xbf, 0xce, 0x1e, 0x17,
	0xca, 0x9d, 0x60, 0x51, 0x15, 0xa4, 0xc7, 0xee,
	0x78, 0xa8, 0x80, 0x28, 0x36, 0xf1, 0x09, 0x26,
	0x55, 0x21, 0x82, 0x54, 0x62, 0xbb, 0x5c, 0xbf,
	0x92, 0x81, 0x7d, 0xf4, 0x30, 0xb0, 0xa0, 0xd1,
	0x79, 0x3e, 0x03, 0xd9, 0x17, 0xbf, 0xa2, 0x99,
	0x49, 0x9e, 0x9c, 0xcc, 0x11, 0x91, 0x43, 0x44,
	0x71, 0xd1, 0xc8, 0xea, 0x8b, 0xa1, 0xb4, 0xb5,
	0xbd, 0xe4, 0x6e, 0x53, 0xc4, 0x28, 0xd8, 0xc8,
	0x5e, 0x4b, 0x6c, 0x86, 0xdc, 0x17, 0xfe, 0x35,
	0x6d, 0x0a, 0x63, 0x64, 0x3e, 0x1c, 0x09, 0x63,
	0xa7, 0xc2, 0x75, 0xa2, 0xa8, 0x49, 0x5d, 0x4f,
	0xfc, 0xe3, 0x5d, 0x14, 0xfa, 0xaa, 0x37, 0xeb,
	0x99, 0x9d, 0xab, 0xc5, 0x6e, 0xaa, 0x51, 0x8b,
	0xe4, 0x94, 0xba, 0xab, 0x74, 0xd0, 0x48, 0x63,
	0xbc, 0xe5, 0x17, 0x2c, 0x66, 0x10, 0x38, 0xf6,
	0xd1, 0xc0, 0x7b, 0x81, 0xde, 0x44, 0x8b, 0x32,
	0x0e, 0x71, 0x0a, 0xae, 0x84, 0x7f, 0xb4, 0xde,
	0x9c, 0x03, 0xd2, 0x25, 0xab, 0xce, 0x69, 0x10,
	0x9b, 0x1e, 0xe0, 0x5f, 0xbe, 0xb5, 0xf8, 0x35,
	0x52, 0x9e, 0xc2, 0x6c, 0xd5, 0x97, 0x14, 0x6e,
	0x90, 0x1d, 0x3a, 0xac, 0xa6, 0xcd, 0xac, 0xa7,
	0xa7, 0x93, 0xa0, 0x2e, 0x25, 0x8d, 0x26, 0x11,
	0xa1, 0x53, 0x2e, 0x35, 0x44, 0x11, 0xd1, 0x91,
	0xb6, 0x6f, 0x7f, 0xf2, 0x10, 0x52, 0xf1, 0x16,
	0x25, 0xc6, 0xaa, 0x83, 0xb7, 0x94, 0x1d, 0xc4,
	0x72, 0xda, 0xce, 0x3b, 0x84, 0x92, 0x79, 0x87,
	0x07, 0xfa, 0x24, 0xa9, 0xea, 0x7c, 0x81, 0xa4,
	0x74, 0x3a, 0xe6, 0x3a, 0xde, 0x41, 0xd9, 0xca,
	0x8f, 0x5d, 0x2b, 0x34, 0x49, 0xed, 0xf8, 0x63,
	0x24, 0x95, 0x27, 0x64, 0xe5, 0x8c, 0x11, 0x9d,
	0xcd, 0x29, 0x8f, 0xb5, 0x4b, 0xc6, 0xed, 0x2c,
	0x7d, 0x94, 0x5f, 0x31, 0x0e, 0xc7, 0xc7, 0x86,
	0xfe, 0xac, 0xe9, 0x63, 0x8f, 0xc4, 0x32, 0xef,
	0x78, 0x44, 0x7e, 0x48, 0x35, 0xa1, 0x9c, 0x84,
	0x09, 0x0a, 0x7b, 0x7f, 0x04, 0xdd, 0x84, 0xe9,
	0x52, 0x30, 0xdc, 0x5f, 0xe8, 0x84, 0xe3, 0x01,
	0xee, 0x36, 0xee, 0x88, 0xb1, 0x5d, 0x5f, 0x37,
	0x81, 0x38, 0xdc, 0x90, 0x97, 0xe5, 0xd4, 0x4b,
	0x87, 0x5f, 0x12, 0xf3, 0x4c, 0xda, 0x7e, 0xc2,
	0x97, 0xf0, 0x02, 0x0e, 0x3c, 0x54, 0xbe, 0x47,
	0x81, 0x98, 0x9c, 0x55, 0xcd, 0xce, 0x8e, 0x7a,
	0x07, 0xa2, 0xad, 0x82, 0x40, 0xb9, 0xe8, 0x62,
	0x68, 0x7b, 0x21, 0x64, 0x82, 0x12, 0xdd, 0xeb,
	0xf9, 0x88, 0xa1, 0xd3, 0xed, 0xde, 0x37, 0x34,
	0xe6, 0xc9, 0x51, 0x00, 0x74, 0x55, 0xcc, 0x0d,
}

var sampleAdoptHeader = Header{
	Version:          0,
	HardwareAddr:     []byte{0x74, 0x83, 0xc2, 0x0f, 0x15, 0xb0},
	flagMask:         1,
	iv:               []byte{0xe4, 0xa5, 0x12, 0xef, 0x15, 0x4e, 0x75, 0x7f, 0x65, 0x5c, 0x7f, 0x43, 0x1b, 0x80, 0x16, 0xd5},
	payloadVersion:   1,
	payloadLength:    384,
	EncryptedAES:     true,
	ZLibCompressed:   false,
	SnappyCompressed: false,
	EncryptedGCM:     false,
	aad:              sampleAdopt[0:40],
}

func TestDecodeAdoptHeader(t *testing.T) {
	r := bytes.NewReader(sampleAdopt)
	out, err := DecodeHeader(r)
	assert.Nil(t, err, "successful decode should not return any errors")
	assert.Equal(t, sampleAdoptHeader, out, "response should equal sample")
}

func TestDecodeAdoptPayload(t *testing.T) {
	r := bytes.NewReader(sampleAdopt)
	inform, err := DecodeHeader(r)
	assert.Nil(t, err, "if this fails, look at TestDecodeHeader")
	payload, err := inform.DecodePayload(r, "")
	assert.Nil(t, err, "payload failed? we should check more specific error here")
	assert.True(t, json.Valid(payload), "payload is not valid json, so decode likely failed")
	t.Logf("payload: %s", payload)
}
