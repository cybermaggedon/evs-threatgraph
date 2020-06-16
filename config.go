package main

import (
	"time"
)

type Config struct {
	url  string
	max_idle_conns    uint
	max_idle_conns_per_host  uint
	connect_timeout    time.Duration
	refresh_time    time.Duration
}

func NewConfig() *Config {
	return &Config{
		url: "http://threatgraph:8080/rest/v2",
		max_idle_conns: 50,
		max_idle_conns_per_host: 5,
		connect_timeout: 5 * time.Second,
		refresh_time: 30 * time.Second,
	}
}

func (c Config) Url(val string) *Config {
	c.url = val
	return &c
}

func (c Config) MaxIdleConns(val uint) *Config {
	c.max_idle_conns = val
	return &c
}

func (c Config) MaxIdleConnsPerHost(val uint) *Config {
	c.max_idle_conns_per_host = val
	return &c
}

func (c Config) ConnectTimeout(val time.Duration) *Config {
	c.connect_timeout = val
	return &c
}

func (c Config) RefreshTime(val time.Duration) *Config {
	c.refresh_time = val
	return &c
}
