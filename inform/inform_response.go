package inform

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/golang/snappy"
	"github.com/jda/nanofi/pkcs7"
)

/*
make interface for responses with serialize func
pass things implementing interface to NewResponse, which returns
data freshly packed to send to client using same settings client used
to when it sent request

useful examples:
https://github.com/jrjparks/OpnFi-rs/blob/master/lib_opnfi/src/inform/payload/mod.rs
https://community.ui.com/questions/AP-Upgrade-to-3-7-21-5389-fails/6d6c8ce1-f728-416b-aa86-7ffb25977c90
*/

type informResponse interface {
	JSON() ([]byte, error)
}

// NoOpResponse is a noop response...
type NoOpResponse struct {
	Kind            string `json:"_type"`
	IntervalSeconds uint64 `json:"interval"`
	ServerTime      string `json:"server_time_in_utc"`
}

// JSON returns json representation of response
func (r NoOpResponse) JSON() (response []byte, err error) {
	response, err = json.Marshal(r)
	return response, err
}

// NewNoOpResponse generates a new NoOpResponse bundle
func NewNoOpResponse(sleepSeconds uint64) NoOpResponse {
	st := unifiServerTime()
	nr := NoOpResponse{"noop", sleepSeconds, st}
	return nr
}

// NewResponse serializes a unifi inform response
func (ih *Header) NewResponse(ir informResponse) (encoded []byte, err error) {
	payload, err := ir.JSON()
	if err != nil {
		return nil, fmt.Errorf("response payload encode failed: %w", err)
	}

	// compress
	if ih.SnappyCompressed {
		payload = snappy.Encode(nil, payload)
	} else if ih.ZLibCompressed {
		ih.ZLibCompressed = false
		// must call syncFlagMask() before serializing
		glog.Warningf("ZLib: not implemented, unsetting header flag and #YOLO")
	}

	// pad if AES without GCM
	if ih.EncryptedAES && !ih.EncryptedGCM {
		payload, err = pkcs7.Pad(payload, aes.BlockSize)
		if err != nil {
			return nil, fmt.Errorf("payload padding failed: %w", err)
		}
		glog.Infof("payload padded: %+v", payload)
	}

	glog.Infof("headers: %+v", ih)

	ih.syncFlagMask()

	// build header
	hdr := make([]byte, 0, 40)
	hdrBuf := bytes.NewBuffer((hdr))
	binary.Write(hdrBuf, binary.BigEndian, []byte(magicHeader))
	binary.Write(hdrBuf, binary.BigEndian, ih.Version)
	binary.Write(hdrBuf, binary.BigEndian, ih.HardwareAddr)
	binary.Write(hdrBuf, binary.BigEndian, ih.flagMask)

	iv, err := genIV()
	if err != nil {
		return nil, err
	}
	binary.Write(hdrBuf, binary.BigEndian, iv)

	binary.Write(hdrBuf, binary.BigEndian, ih.payloadVersion)
	pl := len(payload)
	binary.Write(hdrBuf, binary.BigEndian, uint32(pl))

	// encrypt
	hdr = hdrBuf.Bytes()
	message := make([]byte, 0, pl)
	if ih.EncryptedAES && !ih.EncryptedGCM {
		message, err = encodeAESCBC(ih.encKey, iv, payload)
		if err != nil {
			return nil, err
		}
	} else if ih.EncryptedGCM {
		message, err = encodeAESGCM(ih.encKey, iv, payload, hdr)
		if err != nil {
			return nil, err
		}
	} else {
		message = payload
	}
	glog.Infof("payload size pre: %d, post: %d", pl, len(message))
	out := make([]byte, 0, pl+40)
	out = append(out, hdr...)
	out = append(out, message...)

	return out, nil
}

func zLibEncode(payload []byte) (out []byte, err error) {
	var b bytes.Buffer

	w := zlib.NewWriter(&b)
	_, err = w.Write(payload)
	if err != nil {
		return out, err
	}
	w.Close()
	return b.Bytes(), err
}

func encodeAESCBC(key []byte, iv []byte, pt []byte) (ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return ct, err
	}
	ct = make([]byte, len(pt))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, pt)
	return ct, nil
}

func encodeAESGCM(key []byte, iv []byte, pt []byte, aad []byte) (ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return ct, err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return ct, err
	}

	ct = aesgcm.Seal(nil, iv, pt, aad)

	return ct, nil
}

func unifiServerTime() string {
	t := time.Now().Unix()
	return fmt.Sprintf("%d", t)
}

func genIV() (iv []byte, err error) {
	iv = make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		return iv, fmt.Errorf("could not generate iv: %w", err)
	}
	return iv, nil
}
