package main

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	OPERATION_CHAIN = "uk.gov.gchq.gaffer.operation.OperationChain"
	ADD_ELEMENTS = "uk.gov.gchq.gaffer.operation.impl.add.AddElements"
)

type EdgeKey struct {
	Source      string
	Destination string
	Group       string
}

type EntityKey struct {
	Vertex string
	Group  string
}

type Gaffer struct {
	Config
	edge_buffer   map[EdgeKey]*Edge
	entity_buffer map[EntityKey]*Entity
	bufferq       chan *Update
	loadq         chan *map[string]interface{}
}

type Update struct {
	entities []*Entity
	edges    []*Edge
}

func (c Config) Build() (*Gaffer, error) {
	g := &Gaffer{
		Config:        c,
		edge_buffer:   map[EdgeKey]*Edge{},
		entity_buffer: map[EntityKey]*Entity{},
		bufferq:       make(chan *Update, 5000),
		loadq:         make(chan *map[string]interface{}, 50),
	}

	go g.Loader()
	go g.BufferManager()

	return g, nil
}

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

	// Refresh idle connections every Xs
	go func() {
		for range time.Tick(g.refresh_time) {
			tp.CloseIdleConnections()
		}
	}()

	for {

		b := <-g.loadq

		j, err := json.Marshal(&b)
		if err != nil {
			log.Printf("Couldn't marshal json: %s", err.Error())
			return nil
		}

		fmt.Println(string(j))

		retries := 50

		for {

			req, _ := http.NewRequest("POST",
				g.url+"/graph/operations/execute",
				strings.NewReader(string(j)))
			req.ContentLength = int64(len(j))
			req.Header.Set("Content-Type", "application/json")

			response, err := client.Do(req)
			if err != nil {
				log.Printf("Couldn't make HTTP request: %s",
					err.Error())
				retries--
				if retries <= 0 {
					log.Print("Give up")
					break
				} else {
					log.Print("Retrying...")
					time.Sleep(time.Second)
					continue
				}
			}

			rtn, _ := ioutil.ReadAll(response.Body)
			response.Body.Close()

			if response.StatusCode == 200 {
				break
			}

			log.Printf("Gaffer POST error, status %d",
				response.StatusCode)
			log.Printf("Error: %s", rtn)
			retries--
			if retries <= 0 {
				log.Print("Give up")
				break
			} else {
				log.Print("Retrying...")
				time.Sleep(time.Second)
			}

		}

	}

	return nil
}

func (g *Gaffer) BufferManager() {

	// FIXME: Make configurable
	ticker := time.NewTicker(2 * time.Second)

	for {

		select {
		case <-ticker.C:

			elts := []interface{}{}

			for _, v := range g.edge_buffer {
				elts = append(elts, v.ToGaffer())
			}

			for _, v := range g.entity_buffer {
				elts = append(elts, v.ToGaffer())
			}

			op := map[string]interface{}{
				"class": ADD_ELEMENTS,
				"validate": true,
				"skipInvalidElements": false,
				"input": elts,
			}

			if len(elts) > 0 {
				g.loadq <- &op
			}

			g.edge_buffer = map[EdgeKey]*Edge{}
			g.entity_buffer = map[EntityKey]*Entity{}

		case update := <-g.bufferq:

			g.AddBuffer(update)

		}
	}

}

func (g *Gaffer) AddEntity(e *Entity) {

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

func (g *Gaffer) AddEdge(e *Edge) {

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

func (g *Gaffer) AddBuffer(u *Update) {

	for _, v := range u.entities {
		g.AddEntity(v)
	}

	for _, v := range u.edges {
		g.AddEdge(v)
	}

}

func (g *Gaffer) AddElements(entities []*Entity, edges []*Edge) {
	g.bufferq <- &Update{
		entities: entities,
		edges:    edges,
	}

}
