package main

import (
	"flag"
	"net/http"

	"github.com/golang/glog"
)

func init() {
	flag.Set("logtostderr", "true")
}

func main() {
	listenAddr := flag.String("listen", ":8080", "IP and port on which to listen")
	flag.Parse()

	http.HandleFunc("/inform", informHandler)

	glog.Infof("about to listen on: %s", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		panic(err)
	}
}
