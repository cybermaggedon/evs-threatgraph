package main

import (
	"github.com/cybermaggedon/evs-golang-api"
	"log"
	"os"
	"strconv"
	"time"
)

// Configuration settings for Gaffer
type Config struct {
	*evs.Config

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

	bc := evs.NewConfig("evs-threatgraph", "withioc", nil)

	c := &Config{
		Config:                  bc,
		url:                     "http://gaffer-threat:8080/rest/v2",
		max_idle_conns:          50,
		max_idle_conns_per_host: 5,
		connect_timeout:         5 * time.Second,
		refresh_time:            30 * time.Second,
		flush_time:              1 * time.Second,
	}

	// Override configuration with values set in environment
	if val, ok := os.LookupEnv("GAFFER_URL"); ok {
		c.Url(val)
	}
	if val, ok := os.LookupEnv("MAX_IDLE_CONNS"); ok {
		max, _ := strconv.Atoi(val)
		c.MaxIdleConns(uint(max))
	}
	if val, ok := os.LookupEnv("MAX_IDLE_CONNS_PER_HOST"); ok {
		max, _ := strconv.Atoi(val)
		c.MaxIdleConnsPerHost(uint(max))
	}
	if val, ok := os.LookupEnv("CONNECT_TIMEOUT"); ok {
		dur, err := time.ParseDuration(val)
		if err != nil {
			log.Print(err)
		}
		c.ConnectTimeout(dur)
	}
	if val, ok := os.LookupEnv("REFRESH_TIME"); ok {
		dur, err := time.ParseDuration(val)
		if err != nil {
			log.Print(err)
		}
		c.RefreshTime(dur)
	}
	if val, ok := os.LookupEnv("FLUSH_TIME"); ok {
		dur, err := time.ParseDuration(val)
		if err != nil {
			log.Print(err)
		}
		c.FlushTime(dur)
	}

	return c

}

// Set Gaffer URL setting
func (c *Config) Url(val string) {
	c.url = val
}

// Set max idle connection count
func (c *Config) MaxIdleConns(val uint) {
	c.max_idle_conns = val
}

// Set max idle connection per host count
func (c *Config) MaxIdleConnsPerHost(val uint) {
	c.max_idle_conns_per_host = val
}

// Set connection setup timeout
func (c *Config) ConnectTimeout(val time.Duration) {
	c.connect_timeout = val
}

// Set refresh interval for idle connections
func (c *Config) RefreshTime(val time.Duration) {
	c.refresh_time = val
}

// Set buffer flush interval
func (c *Config) FlushTime(val time.Duration) {
	c.flush_time = val
}
