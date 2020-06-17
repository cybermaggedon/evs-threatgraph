package main

import (
	evs "github.com/cybermaggedon/evs-golang-api"
	"log"
	"os"
	"strconv"
	"time"
)

const ()

type ThreatGraph struct {

	// Embed EventAnalytic framework
	evs.EventAnalytic

	// Gaffer management
	gaffer *Gaffer
}

// Initialisation
func (a *ThreatGraph) Init(binding string) error {

	// Get new configuration
	c := NewConfig()

	// Override configuration with values set in environment
	if val, ok := os.LookupEnv("GAFFER_URL"); ok {
		c = c.Url(val)
	}
	if val, ok := os.LookupEnv("MAX_IDLE_CONNS"); ok {
		max, _ := strconv.Atoi(val)
		c = c.MaxIdleConns(uint(max))
	}
	if val, ok := os.LookupEnv("MAX_IDLE_CONNS_PER_HOST"); ok {
		max, _ := strconv.Atoi(val)
		c = c.MaxIdleConnsPerHost(uint(max))
	}
	if val, ok := os.LookupEnv("CONNECT_TIMEOUT"); ok {
		dur, err := time.ParseDuration(val)
		if err != nil {
			return err
		}
		c = c.ConnectTimeout(dur)
	}
	if val, ok := os.LookupEnv("REFRESH_TIME"); ok {
		dur, err := time.ParseDuration(val)
		if err != nil {
			return err
		}
		c = c.RefreshTime(dur)
	}
	if val, ok := os.LookupEnv("FLUSH_TIME"); ok {
		dur, err := time.ParseDuration(val)
		if err != nil {
			return err
		}
		c = c.FlushTime(dur)
	}

	// Initialise Gaffer from configuration
	var err error
	a.gaffer, err = c.Build()
	if err != nil {
		return err
	}

	// Initialise analytic framework
	a.EventAnalytic.Init(binding, []string{}, a)
	return nil
}

// Event handler for new events.
func (a *ThreatGraph) Event(ev *evs.Event, props map[string]string) error {

	// Convert event to threatgraph model
	entities, edges, _ := DescribeThreatElements(ev)

	// Send elements to  Gaffer loader
	a.gaffer.AddElements(entities, edges)

	return nil

}

func main() {

	// Initialise analytic object
	a := &ThreatGraph{}

	// Get input queue name
	binding, ok := os.LookupEnv("INPUT")
	if !ok {
		binding = "ioc"
	}

	// Initialise analytic with input queue
	err := a.Init(binding)
	if err != nil {
		log.Printf("Init: %v", err)
		return
	}

	log.Print("Initialisation complete.")

	// Handle events until shutdown
	a.Run()

	log.Print("Shutdown complete.")

}
