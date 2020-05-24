package main

import (
	"flag"
	"net/http"

	"github.com/golang/glog"
	"github.com/jda/nanofi/inform"
)

func init() {
	flag.Set("logtostderr", "true")
}

func main() {
	http.HandleFunc("/inform", handler)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		glog.Warningf("%s: unsupported method %s on %s", r.RemoteAddr, r.Method, r.RequestURI)
		http.Error(w, "invalid method for this endpoint", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-type")
	if r.Header.Get("Content-type") != inform.InformContentType {
		glog.Warningf("%s: invalid content-type %s on %s", r.RemoteAddr, contentType, r.RequestURI)
		http.Error(w, "invalid payload", http.StatusUnsupportedMediaType)
		return
	}

	inform, err := inform.DecodeHeader(r.Body)
	if err != nil {
		glog.Errorf("%s: could not parse inform header: %w", r.RemoteAddr, err)
	}

	payload, err := inform.DecodePayload(r.Body, "")
	if err != nil {
		glog.Errorf("%s: could not decrypt inform payload: %w", r.RemoteAddr, err)
	}

	glog.Infof("%s", payload)
	return

}
