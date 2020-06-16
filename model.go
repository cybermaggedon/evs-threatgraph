package main

import (
	"time"
	evs "github.com/cybermaggedon/evs-golang-api"
	"github.com/golang/protobuf/ptypes"
)

const (
	ENTITY = "uk.gov.gchq.gaffer.data.element.Entity"
	EDGE = "uk.gov.gchq.gaffer.data.element.Edge"
	TIMESTAMP_SET = "uk.gov.gchq.gaffer.time.RBMBackedTimestampSet"
	TIME_BUCKET = "HOUR"
)

type PropertyMap map[string]interface{}

type TimestampSet map[uint64]bool

type Edge struct {
	Source string
	Destination string
	Group string
	Count uint64
	Time TimestampSet
}

func NewEdge(source, destination, group string) *Edge {
	e := Edge{
		Source: source,
		Destination: destination,
		Group: group,
		Time: TimestampSet{},
	}
	return &e
}

func (e *Edge) AddTime(tm time.Time) *Edge {
	e.Time[uint64(tm.Unix())] = true
	return e
}

func (e *Edge) AddCount(count uint64) *Edge {
	e.Count += count
	return e
}

func (e *Edge) Merge(e2 *Edge) {

	e.Count += e2.Count

	for k, _ := range e2.Time {
		e.Time[k] = true
	}
	
}

func (e *Edge) ToGaffer() map[string]interface{} {

	tset := make([]uint64, 0, len(e.Time))

	for v, _ := range e.Time {
		tset = append(tset, v)
	}
	
	return map[string]interface{}{
		"class": EDGE,
		"group": e.Group,
		"source": e.Source,
		"destination": e.Destination,
		"directed": true,
		"properties": PropertyMap{
			TIMESTAMP_SET: PropertyMap{
				"timeBucket": TIME_BUCKET,
				"timestamps": tset,
			},
			"count": e.Count,
		},
	}
}

type Entity struct {
	Vertex string
	Group string
	Count uint64
	Time TimestampSet
}

func NewEntity(vertex, group string) *Entity {
	return &Entity{
		Vertex: vertex,
		Group: group,
		Time: TimestampSet{},
	}
}

func (e *Entity) AddTime(tm time.Time) *Entity {
	e.Time[uint64(tm.Unix())] = true
	return e
}

func (e *Entity) AddCount(count uint64) *Entity {
	e.Count += count
	return e
}

func (e *Entity) Merge(e2 *Entity) {

	e.Count += e2.Count

	for k, _ := range e2.Time {
		e.Time[k] = true
	}
	
}

func (e *Entity) ToGaffer() map[string]interface{} {

	tset := make([]uint64, 0, len(e.Time))

	for v, _ := range e.Time {
		tset = append(tset, v)
	}
	
	return map[string]interface{}{
		"class": ENTITY,
		"group": e.Group,
		"vertex": e.Vertex,
		"properties": PropertyMap{
			TIMESTAMP_SET: PropertyMap{
				"timeBucket": TIME_BUCKET,
				"timestamps": tset,
			},
			"count": e.Count,
		},
	}
}

func NewIp(address string) *Entity {
	return NewEntity(address, "ip")
}

func NewDevice(v string) *Entity {
	return NewEntity(v, "device")
}

func NewHostname(v string) *Entity {
	return NewEntity(v, "hostname")
}

func NewDomain(v string) *Entity {
	return NewEntity(v, "domain")
}

func NewServer(v string) *Entity {
	return NewEntity(v, "server")
}

func NewUseragent(v string) *Entity {
	return NewEntity(v, "useragent")
}

func NewIpflow(src, dest string) *Edge {
	return NewEdge(src, dest, "ipflow")
}

func NewHasip(s, d string) *Edge {
	return NewEdge(s, d, "hasip")
}

func NewDnsquery(s, d string) *Edge {
	return NewEdge(s, d, "dnsquery")
}

func NewDnsresolve(s, d string) *Edge {
	return NewEdge(s, d, "dnsresolve")
}

func NewIndomain(s, d string) *Edge {
	return NewEdge(s, d, "indomain")
}

func NewRequests(s, d string) *Edge {
	return NewEdge(s, d, "requests")
}

func NewServes(s, d string) *Edge {
	return NewEdge(s, d, "serves")
}

func NewUses(s, d string) *Edge {
	return NewEdge(s, d, "uses")
}

// Handle a single JSON object.
func DescribeThreatElements(ev *evs.Event) ([]*Entity, []*Edge, error) {

	tm, _ := ptypes.Timestamp(ev.Time)

	tm = tm.Round(time.Second)

	var sip, dip string

	for _, addr := range ev.Src {
		if addr.Protocol == evs.Protocol_ipv4 {
			sip = evs.Int32ToIp(addr.Address.GetIpv4()).String()
		}
		if addr.Protocol == evs.Protocol_ipv6 {
			sip = evs.BytesToIp(addr.Address.GetIpv6()).String()
		}
	}

	for _, addr := range ev.Dest {
		if addr.Protocol == evs.Protocol_ipv4 {
			dip = evs.Int32ToIp(addr.Address.GetIpv4()).String()
		}
		if addr.Protocol == evs.Protocol_ipv6 {
			dip = evs.BytesToIp(addr.Address.GetIpv6()).String()
		}
	}

	entities := []*Entity{}
	edges := []*Edge{}

	// Add ipflow edge between two IPs.
	sipe := NewIp(sip).AddTime(tm).AddCount(1)
	entities = append(entities, sipe)

	dipe := NewIp(dip).AddTime(tm).AddCount(1)
	entities = append(entities, dipe)

	flowe := NewIpflow(sip, dip).
		AddTime(tm).
		AddCount(1)
	edges = append(edges, flowe)

	deve := NewDevice(ev.Device).
		AddTime(tm).
		AddCount(1)
	if ev.Origin == evs.Origin_device {
		entities = append(entities, deve)
		hasipe := NewHasip(ev.Device, sip).
			AddTime(tm).
			AddCount(1)
		edges = append(edges, hasipe)
	} else if ev.Origin == evs.Origin_network {
		entities = append(entities, deve)
		hasipe := NewHasip(ev.Device, dip).
			AddTime(tm).
			AddCount(1)
		edges = append(edges, hasipe)
	}

	switch ev.Detail.(type) {
	case *evs.Event_DnsMessage:

		msg := ev.GetDnsMessage()
		
		if msg.Type == evs.DnsMessageType_query {
			for _, v := range msg.Query {
				if v.Name != "" {
					hoste := NewHostname(v.Name).
						AddTime(tm).
						AddCount(1)
					entities = append(entities, hoste)
					dnsqe := NewDnsquery(sip, v.Name).
						AddTime(tm).
						AddCount(1)
					edges = append(edges, dnsqe)
				}

				dmn := ExtractDomain(v.Name)

				if dmn != "" {
					dmne := NewDomain(dmn).
						AddTime(tm).
						AddCount(1)
					entities = append(entities, dmne)
					inde := NewIndomain(v.Name, dmn).
						AddTime(tm).
						AddCount(1)
					edges = append(edges, inde)
				}

			}
		} else if msg.Type == evs.DnsMessageType_response {
			for _, v := range msg.Answer {
				if v.Name != "" && v.Address != nil {
					addr := evs.AddressToString(v.Address)
					hoste := NewHostname(v.Name).
						AddTime(tm).
						AddCount(1)
					entities = append(entities, hoste)
					dnsqe := NewDnsresolve(v.Name, addr).
						AddTime(tm).
						AddCount(1)
					edges = append(edges, dnsqe)
				}

				dmn := ExtractDomain(v.Name)

				if dmn != "" {
					dmne := NewDomain(dmn).
						AddTime(tm).
						AddCount(1)
					entities = append(entities, dmne)
					inde := NewIndomain(v.Name, dmn).
						AddTime(tm).
						AddCount(1)
					edges = append(edges, inde)
				}

			}
		}

	case *evs.Event_HttpRequest:

		msg := ev.GetHttpRequest()
		host := msg.Header["Host"]
		ua := msg.Header["User-Agent"]

		if host != "" {

			servere := NewServer(host).
				AddTime(tm).
				AddCount(1)
			entities = append(entities, servere)

			requestse := NewRequests(sip, host).
				AddTime(tm).
				AddCount(1)
			edges = append(edges, requestse)

			servese := NewServes(dip, host).
				AddTime(tm).
				AddCount(1)
			edges = append(edges, servese)

		}

		if ua != "" {
			uae := NewUseragent(ua).
				AddTime(tm).
				AddCount(1)
			entities = append(entities, uae)

			usesagent := NewUses(sip, ua).
				AddTime(tm).
				AddCount(1)
			edges = append(edges, usesagent)
		}

	}

	return entities, edges, nil

}

