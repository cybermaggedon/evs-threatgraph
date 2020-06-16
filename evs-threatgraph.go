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

	gaffer *Gaffer
}

// Initialisation
func (a *ThreatGraph) Init(binding string) error {

	c := NewConfig()

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

	var err error
	a.gaffer, err = c.Build()
	if err != nil {
		return err
	}

	a.EventAnalytic.Init(binding, []string{}, a)
	return nil
}

// Event handler for new events.
func (a *ThreatGraph) Event(ev *evs.Event, props map[string]string) error {

	entities, edges, _ := DescribeThreatElements(ev)

	a.gaffer.AddElements(entities, edges)

	return nil

}

func main() {

	a := &ThreatGraph{}

	binding, ok := os.LookupEnv("INPUT")
	if !ok {
		binding = "ioc"
	}

	err := a.Init(binding)
	if err != nil {
		log.Printf("Init: %v", err)
		return
	}

	log.Print("Initialisation complete.")

	a.Run()

	log.Print("Shutdown complete.")

}
