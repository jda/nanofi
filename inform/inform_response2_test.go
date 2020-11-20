package inform

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

var sampleInformResponse2 = []byte{
	0x54, 0x4e, 0x42, 0x55, 0x00, 0x00, 0x00, 0x00,
	0xf4, 0x92, 0xbf, 0x88, 0xb2, 0x3a, 0x00, 0x09,
	0xd8, 0x37, 0xac, 0x27, 0xda, 0x76, 0x50, 0x76,
	0xbc, 0xf5, 0x67, 0xc9, 0x92, 0xde, 0xf7, 0x6e,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x6d,
	0xbe, 0x6f, 0x1f, 0x3c, 0xa5, 0xa7, 0x9c, 0x30,
	0xb8, 0x0e, 0xfa, 0x76, 0xac, 0x9f, 0x0c, 0x38,
	0x41, 0x5b, 0xd1, 0xf1, 0xe0, 0x09, 0xc2, 0x6e,
	0x2c, 0x5f, 0x36, 0xad, 0x93, 0x7c, 0x46, 0xdd,
	0xba, 0x16, 0xde, 0x2f, 0x5a, 0x98, 0xa3, 0x09,
	0xd5, 0xf3, 0xfc, 0xf7, 0x74, 0x4b, 0xc5, 0xa0,
	0xf9, 0x45, 0x22, 0x6e, 0xe0, 0x51, 0x75, 0xf3,
	0xb2, 0x2b, 0xc1, 0x44, 0x0f, 0x8c, 0x2f, 0x8c,
	0x68, 0x7a, 0xce, 0x1c, 0xed, 0x4d, 0x78, 0x12,
	0xb2, 0xbd, 0xe4, 0xa7, 0x11, 0x32, 0xbc, 0x6c,
	0x46, 0x90, 0x58, 0xea, 0xaa, 0x23, 0x56, 0xa6,
	0xa5, 0xd8, 0x1a, 0x8a, 0xa4, 0xf4, 0x83, 0xf9,
	0x96, 0x35, 0x33, 0x71, 0xa9, 0x10, 0x27, 0x5c,
	0xd8, 0xb1, 0x0f, 0xa6, 0x9d, 0x83, 0x26, 0x0e,
	0x92, 0x2d, 0xae, 0x66, 0x89, 0xbd, 0x10, 0x1b,
	0x48, 0x82, 0x88, 0xf6, 0x85, 0xa7, 0x28, 0x0b,
	0xf5, 0x0e, 0x8b, 0x6b, 0x2c, 0xaa, 0xd3, 0xf1,
	0xe7, 0x3a, 0xc1, 0x4e, 0x75, 0x00, 0x43, 0x87,
	0xde, 0x94, 0x9c, 0xf5, 0xc2, 0x19, 0x18, 0x78,
	0xd5, 0x00, 0x55, 0x98, 0x5b, 0x61, 0xe6, 0x06,
	0xce, 0x35, 0x6c, 0xc1, 0x7b, 0xc6, 0x2d, 0xa5,
	0x2c, 0xe3, 0xf4, 0xe9, 0x69, 0xc4, 0x28, 0x41,
	0xc5, 0xc1, 0xb9, 0x5d, 0x73, 0xa2, 0x21, 0xa2,
	0x94, 0x41, 0xb8, 0xa0, 0x5c, 0x6e, 0x9b, 0x3e,
	0x7b, 0xcf, 0x01, 0xed, 0x7c, 0xcc, 0xca, 0xd9,
	0x43, 0x8f, 0xbf, 0x6d, 0x65, 0x7f, 0x5e, 0xab,
	0xdb, 0x57, 0x76, 0x7c, 0xee, 0x98, 0x05, 0x89,
	0x78, 0x41, 0xd6, 0xfa, 0xec, 0x0d, 0x41, 0xea,
	0x97, 0x27, 0x35, 0x39, 0x40, 0xc0, 0xd3, 0x4e,
	0x6c, 0x3b, 0xca, 0x4f, 0x43, 0x37, 0x48, 0x1a,
	0xac, 0xd8, 0xa1, 0x0c, 0x3f, 0x33, 0xcc, 0xaf,
	0xdd, 0xd0, 0xd8, 0x58, 0xc6, 0x3e, 0x42, 0xbb,
	0xc2, 0x80, 0x96, 0xc0, 0x9a, 0xcb, 0xef, 0x39,
	0xf3, 0x3a, 0x60, 0x0d, 0x3d, 0x8f, 0x9b, 0x5e,
	0xf7, 0xa5, 0xb5, 0x9b, 0xb8, 0x76, 0x73, 0x70,
	0x2a, 0x34, 0xc5, 0xdf, 0x7a, 0x33, 0xc5, 0x21,
	0x2e, 0xe6, 0x9b, 0x23, 0x97, 0x51, 0x4c, 0x00,
	0xc1, 0x28, 0xac, 0x16, 0x9f, 0x6e, 0x1e, 0xf6,
	0x5b, 0x14, 0x38, 0x8f, 0x84, 0x7c, 0xc3, 0x3d,
	0x7c, 0x36, 0xe3, 0x99, 0xfb, 0x5f, 0xaa, 0x93,
	0xbd, 0xe2, 0xbb, 0x1b, 0x46, 0x30, 0x04, 0xbc,
	0x03, 0xd3, 0xff, 0x6e, 0x14, 0x1b, 0xfe, 0x23,
	0xec, 0xf6, 0x7d, 0x57, 0xb0, 0x21, 0xb3, 0x6c,
	0x5d, 0x24, 0x1b, 0xc1, 0x28, 0xe6, 0xd3, 0x08,
	0xca, 0xb5, 0x7b, 0x8f, 0x3c, 0x95, 0x8f, 0x4d,
	0x94, 0x37, 0xcf, 0x2d, 0x10,
}

var sampleInformResponse2Header = Header{
	Version:          0,
	HardwareAddr:     []byte{0xf4, 0x92, 0xbf, 0x88, 0xb2, 0x3a},
	flagMask:         9,
	iv:               []byte{0xd8, 0x37, 0xac, 0x27, 0xda, 0x76, 0x50, 0x76, 0xbc, 0xf5, 0x67, 0xc9, 0x92, 0xde, 0xf7, 0x6e},
	payloadVersion:   1,
	payloadLength:    365,
	EncryptedAES:     true,
	ZLibCompressed:   false,
	SnappyCompressed: false,
	EncryptedGCM:     true,
	aad:              sampleInformResponse2[0:40],
}

func TestDecodeInformResponse2(t *testing.T) {
	r := bytes.NewReader(sampleInformResponse2)
	out, err := DecodeHeader(r)
	assert.Nil(t, err, "successful decode should not return any errors")
	assert.Equal(t, sampleInformResponse2Header, out, "response should equal sample")

}

func TestDecodeInformResponse2Payload(t *testing.T) {
	r := bytes.NewReader(sampleInformResponse2)
	inform, err := DecodeHeader(r)
	assert.Nil(t, err, "if this fails, look at TestDecodeInformResponse2")
	payload, err := inform.DecodePayload(r, "")
	assert.Nil(t, err, "payload failed? we should check more specific error here")
	assert.True(t, json.Valid(payload), "payload is not valid json, so decode likely failed")
	t.Logf("payload: %s", payload)
}
