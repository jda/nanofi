package main

import (
	"bytes"
	"net/http"

	"github.com/golang/glog"
	"github.com/jda/nanofi/inform"
)

func informHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		glog.Warningf("%s: unsupported method %s on %s", r.RemoteAddr, r.Method, r.RequestURI)
		http.Error(w, "invalid method for this endpoint", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-type")
	if contentType != inform.InformContentType {
		glog.Warningf("%s: invalid content-type %s on %s", r.RemoteAddr, contentType, r.RequestURI)
		http.Error(w, "invalid payload", http.StatusUnsupportedMediaType)
		return
	}

	imsg, err := inform.DecodeHeader(r.Body)
	if err != nil {
		glog.Errorf("%s: could not parse inform header: %s", r.RemoteAddr, err)
		http.Error(w, "inform header error", http.StatusInternalServerError)
		return
	}
	glog.Infof("inform header: %+v", imsg)

	// check if known - hwaddr

	payload, err := imsg.DecodePayload(r.Body, "")
	if err != nil {
		glog.Errorf("%s: could not decrypt inform payload: %s", r.RemoteAddr, err)
		http.Error(w, "payload decrypt error", http.StatusInternalServerError)
		return
	}

	//

	glog.Infof("got request from: %s\n%s", r.RemoteAddr, payload)

	noop := inform.NewNoOpResponse(22)
	// TODO what if we reply in clear? just to test...
	// also need function to set flagMask from flags so it's correct on response...
	res, err := imsg.NewResponse(noop)
	if err != nil {
		glog.Errorf("%s: could not generate response payload: %s", r.RemoteAddr, err)
		http.Error(w, "response generation error", http.StatusInternalServerError)
		return
	}
	glog.Infof("sending response:\n%+v", res)

	resX := bytes.NewBuffer(res)
	dH, err := inform.DecodeHeader(resX)
	if err != nil {
		glog.Fatalf("failed to decode response: %s", err)
	}

	dP, err := dH.DecodePayload(resX, "")
	if err != nil {
		glog.Fatalf("failed to decode response payload: %s", err)
	}
	glog.Infof("got response payload: %s", dP)

	w.Header().Set("Content-Type", inform.InformContentType)
	_, err = w.Write((res))
	if err != nil {
		glog.Errorf("%s: error sending response: %s", r.RemoteAddr, err)
		return
	}

	return

}
