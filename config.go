package main

import (
	"time"
)

// Configuration settings for Gaffer
type Config struct {

	// Gaffer URL
	url string

	// Max idle connection count

	max_idle_conns uint

	// Max idle connection per host count
	max_idle_conns_per_host uint

	// Connection setup timeout
	connect_timeout time.Duration

	// Refresh interval for idle connections
	refresh_time time.Duration

	// Buffer flush interval
	flush_time time.Duration
}

// Create a new configuration with default values
func NewConfig() *Config {
	return &Config{
		url:                     "http://threatgraph:8080/rest/v2",
		max_idle_conns:          50,
		max_idle_conns_per_host: 5,
		connect_timeout:         5 * time.Second,
		refresh_time:            30 * time.Second,
		flush_time:              1 * time.Second,
	}
}

// Set Gaffer URL setting
func (c Config) Url(val string) *Config {
	c.url = val
	return &c
}

// Set max idle connection count
func (c Config) MaxIdleConns(val uint) *Config {
	c.max_idle_conns = val
	return &c
}

// Set max idle connection per host count
func (c Config) MaxIdleConnsPerHost(val uint) *Config {
	c.max_idle_conns_per_host = val
	return &c
}

// Set connection setup timeout
func (c Config) ConnectTimeout(val time.Duration) *Config {
	c.connect_timeout = val
	return &c
}

// Set refresh interval for idle connections
func (c Config) RefreshTime(val time.Duration) *Config {
	c.refresh_time = val
	return &c
}

// Set buffer flush interval
func (c Config) FlushTime(val time.Duration) *Config {
	c.flush_time = val
	return &c
}
