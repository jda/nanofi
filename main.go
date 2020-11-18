package main

import (
	"flag"
	"net/http"
)

func init() {
	flag.Set("logtostderr", "true")
}

func main() {
	processFlags()
	http.HandleFunc("/inform", informHandler)
	if err := http.ListenAndServe(sysConfig.Listen, nil); err != nil {
		panic(err)
	}
}
