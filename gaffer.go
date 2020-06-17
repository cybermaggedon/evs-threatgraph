package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// Constants for Gaffer operation objects
const (
	OPERATION_CHAIN = "uk.gov.gchq.gaffer.operation.OperationChain"
	ADD_ELEMENTS    = "uk.gov.gchq.gaffer.operation.impl.add.AddElements"
)

// Gaffer interface
type Gaffer struct {

	// Configuration
	Config

	// Internal buffer
	edge_buffer   map[EdgeKey]*Edge
	entity_buffer map[EntityKey]*Entity

	// Queue from analytic to buffer managenent
	bufferq chan *Update

	// Queue from  buffer to loader
	loadq chan *map[string]interface{}
}

// The key is used to identify a unique edge for internal buffer management
type EdgeKey struct {
	Source      string
	Destination string
	Group       string
}

// The entity key ise used to identify a unique entity for internal buffer
// management
type EntityKey struct {
	Vertex string
	Group  string
}

// A buffer update is an array of entities and an array of edges
type Update struct {
	entities []*Entity
	edges    []*Edge
}

// Convert a gaffer configuration to a gaffer buffer manager.
func (c Config) Build() (*Gaffer, error) {

	// Initialise Gaffer object
	g := &Gaffer{
		Config:        c,
		edge_buffer:   map[EdgeKey]*Edge{},
		entity_buffer: map[EntityKey]*Entity{},
		bufferq:       make(chan *Update, 5000),
		loadq:         make(chan *map[string]interface{}, 50),
	}

	// Start loader and buffer manager goroutines
	go g.Loader()
	go g.BufferManager()

	return g, nil
}

// Loader goroutines reads objects from the queue, and loads into Gaffer
func (g *Gaffer) Loader() error {

	// Create an HTTP transport and client for Gaffer.
	tp := &http.Transport{
		MaxIdleConnsPerHost: int(g.max_idle_conns_per_host),
		MaxIdleConns:        int(g.max_idle_conns),
	}
	client := &http.Client{
		Transport: tp,
		Timeout:   g.connect_timeout,
	}

	// Refresh idle connections.  Tidying idle connections prevents
	// error/retry on connections which have closed down.
	go func() {
		for range time.Tick(g.refresh_time) {
			tp.CloseIdleConnections()
		}
	}()

	// Loop  forever
	for {

		// Take items from the queue
		b := <-g.loadq

		// Encode as JSON
		j, err := json.Marshal(&b)
		if err != nil {
			log.Printf("Couldn't marshal json: %s", err.Error())
			return nil
		}

		for {

			// Create HTTP request
			req, _ := http.NewRequest("POST",
				g.url+"/graph/operations/execute",
				strings.NewReader(string(j)))
			req.ContentLength = int64(len(j))
			req.Header.Set("Content-Type", "application/json")

			// Send request
			response, err := client.Do(req)
			if err != nil {
				log.Printf("Couldn't make HTTP request: %s",
					err.Error())
				log.Print("Retrying...")
				time.Sleep(10 * time.Second)
				continue
			}

			// Read response
			rtn, _ := ioutil.ReadAll(response.Body)
			response.Body.Close()

			// 200 status = request successful
			if response.StatusCode == 200 {
				break
			}

			// Handle error by retrying
			log.Printf("Gaffer POST error, status %d",
				response.StatusCode)
			log.Printf("Error: %s", rtn)
			log.Print("Retrying...")
			time.Sleep(5 * time.Second)

		}

	}

	return nil
}

// Buffer manager goroutine
func (g *Gaffer) BufferManager() {

	// Buffer flush interval
	ticker := time.NewTicker(g.flush_time)

	// Loop forever, event handle
	for {

		select {

		// First event case, buffer flush  event
		case <-ticker.C:

			// Create elt list
			elts := []interface{}{}

			// Add edges and entities to list
			for _, v := range g.edge_buffer {
				elts = append(elts, v.ToGaffer())
			}
			for _, v := range g.entity_buffer {
				elts = append(elts, v.ToGaffer())
			}

			// If no elements, do nothing
			if len(elts) > 0 {

				// Put elements in an AddElement operation
				op := map[string]interface{}{
					"class":               ADD_ELEMENTS,
					"validate":            true,
					"skipInvalidElements": false,
					"input":               elts,
				}

				// Add operation to load queue for loader
				// goroutine
				g.loadq <- &op

				// Elements have been queued for Gaffer load,
				// can empty buffer
				g.edge_buffer = map[EdgeKey]*Edge{}
				g.entity_buffer = map[EntityKey]*Entity{}

			}

			// If there are updates on the buffer queue,
			// add them to the buffer
		case update := <-g.bufferq:

			g.AddBuffer(update)

		}
	}

}

// Add entity to buffer
func (g *Gaffer) AddEntity(e *Entity) {

	// Entities are stored in a map with a vertex/group key.  If an
	// entity is not in the map, it is copied into the map with the
	// right key.  If already in the map, the count/time information
	// is added to existing entity.

	k := EntityKey{
		Vertex: e.Vertex,
		Group:  e.Group,
	}

	if _, ok := g.entity_buffer[k]; !ok {
		g.entity_buffer[k] = e
		return
	}

	g.entity_buffer[k].Merge(e)

}

// Add entity to buffer
func (g *Gaffer) AddEdge(e *Edge) {

	// Ege are stored in a map with a src/dest/group key.  If an
	// edge is not in the map, it is copied into the map with the
	// right key.  If already in the map, the count/time information
	// is added to existing edge.

	k := EdgeKey{
		Source:      e.Source,
		Destination: e.Destination,
		Group:       e.Group,
	}

	if _, ok := g.edge_buffer[k]; !ok {
		g.edge_buffer[k] = e
		return
	}

	g.edge_buffer[k].Merge(e)

}

// Add elements to the buffer
func (g *Gaffer) AddBuffer(u *Update) {

	for _, v := range u.entities {
		g.AddEntity(v)
	}

	for _, v := range u.edges {
		g.AddEdge(v)
	}

}

// Add entities/edges to the buffer queue
func (g *Gaffer) AddElements(entities []*Entity, edges []*Edge) {
	g.bufferq <- &Update{
		entities: entities,
		edges:    edges,
	}

}
