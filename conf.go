package main

import (
	"flag"
)

// Config for nanofi
type Config struct {
	Listen   string
	ConfFile string
}

var sysConfig Config

func processFlags() {
	listen := flag.String("listen", ":8080", "IP and port on which to listen")
	confFile := flag.String("conf", "conf.toml", "config file")
	flag.Parse()

	sysConfig.Listen = *listen
	sysConfig.ConfFile = *confFile

	loadConf(*confFile)
}

func loadConf(cfName string) {

}

// config flag points to toml config file
// file allows you to define networks
// a network describes SSID, VLAN, etc in general
// devices are members of networks?

// authfile contains CSV of mac addr to secrets, which are tried left to right
// in mem, reloaded on SIGHUP. If device isn't listed here, we ignore it (return http 403)
