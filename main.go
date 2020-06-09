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
	flag.Parse()
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
		glog.Errorf("%s: could not parse inform header: %s", r.RemoteAddr, err)
		http.Error(w, "inform header error", http.StatusInternalServerError)
		return
	}
	glog.Infof("inform header: %+v", inform)

	payload, err := inform.DecodePayload(r.Body, "")
	if err != nil {
		glog.Errorf("%s: could not decrypt inform payload: %s", r.RemoteAddr, err)
		http.Error(w, "payload decrypt error", http.StatusInternalServerError)
		return

	}

	glog.Infof("%s", payload)
	return

}
