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

type Element interface {
	SetGroup(string) Element
	SetClass(string) Element
	AddProperty(string, interface{}) Element
}

type Edge map[string]interface{}

func (e *Edge) SetGroup(group string) Element {
	(*e)["group"] = group
	return Element(e)
}

func (e *Edge) SetClass(class string) Element {
	(*e)["class"] = class
	return Element(e)
}

func (e *Edge) AddProperty(key string, value interface{}) Element {
	// FIXME
	return Element(e)
	if _, ok := (*e)["properties"]; !ok {
		(*e)["properties"] = PropertyMap{}
	}
	(*e)["properties"].(PropertyMap)[key] = value
	return Element(e)
}

func NewEdge(source, destination, group string, directed bool) *Edge {
	e := Edge{
		"source": source,
		"destination": destination,
		"group": group,
//		"directed": directed,
//		"class": EDGE,
	}
	return &e
}

type Entity map[string]interface{}

func (e *Entity) SetGroup(group string) Element {
	(*e)["group"] = group
	return Element(e)
}

func (e *Entity) SetClass(class string) Element {
	(*e)["class"] = class
	return Element(e)
}

func (e *Entity) AddProperty(key string, value interface{}) Element {
	// FIXME
	return Element(e)
	if _, ok := (*e)["properties"]; !ok {
		(*e)["properties"] = PropertyMap{}
	}
	(*e)["properties"].(PropertyMap)[key] = value
	return Element(e)
}

func NewEntity(vertex, group string) *Entity {
	return &Entity{
		"vertex": vertex,
		"group": group,
//		"class": ENTITY,
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
	return NewEdge(src, dest, "ipflow", true)
}

func NewHasip(s, d string) *Edge {
	return NewEdge(s, d, "hasip", true)
}

func NewDnsquery(s, d string) *Edge {
	return NewEdge(s, d, "dnsquery", true)
}

func NewDnsresolve(s, d string) *Edge {
	return NewEdge(s, d, "dnsresolve", true)
}

func NewIndomain(s, d string) *Edge {
	return NewEdge(s, d, "indomain", true)
}

func NewRequests(s, d string) *Edge {
	return NewEdge(s, d, "requests", true)
}

func NewServes(s, d string) *Edge {
	return NewEdge(s, d, "serves", true)
}

func NewUses(s, d string) *Edge {
	return NewEdge(s, d, "uses", true)
}

type TimestampSet PropertyMap

// Create new timtestamp set.
func NewTimestampSet(bucket string) *TimestampSet {
	return nil
	return &TimestampSet{
		TIMESTAMP_SET: PropertyMap{
			"timeBucket": bucket,
			"timestamps": []uint64{},
		},
	}
}

// Add a time to a timestamp set.  We're look at UNIX time here.
func (e *TimestampSet) Add(t time.Time) *TimestampSet {
	return e
	tss := (*e)[TIMESTAMP_SET].(PropertyMap)
	tss["timestamps"] = append(tss["timestamps"].([]uint64),
		uint64(t.Unix()))
	return e
}

// Handle a single JSON object.
func DescribeThreatElements(ev *evs.Event) ([]interface{}, error) {

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

	elts := []interface{}{}

	tset := NewTimestampSet(TIME_BUCKET).Add(tm)

	// Add ipflow edge between two IPs.
	sipe := NewIp(sip).AddProperty("time", tset)
	elts = append(elts, sipe)

	dipe := NewIp(dip).AddProperty("time", tset)
	elts = append(elts, dipe)

	flowe := NewIpflow(sip, dip).AddProperty("time", tset)
	elts = append(elts, flowe)

	deve := NewDevice(ev.Device).AddProperty("time", tset)
	if ev.Origin == evs.Origin_device {
		elts = append(elts, deve)
		hasipe := NewHasip(ev.Device, sip).AddProperty("time", tset)
		elts = append(elts, hasipe)
	} else if ev.Origin == evs.Origin_network {
		elts = append(elts, deve)
		hasipe := NewHasip(ev.Device, dip).AddProperty("time", tset)
		elts = append(elts, hasipe)
	}

	switch ev.Detail.(type) {
	case *evs.Event_DnsMessage:

		msg := ev.GetDnsMessage()
		
		if msg.Type == evs.DnsMessageType_query {
			for _, v := range msg.Query {
				if v.Name != "" {
					hoste := NewHostname(v.Name).
						AddProperty("time", tset)
					elts = append(elts, hoste)
					dnsqe := NewDnsquery(sip, v.Name).
						AddProperty("time", tset)
					elts = append(elts, dnsqe)
				}

				dmn := ExtractDomain(v.Name)

				if dmn != "" {
					dmne := NewDomain(dmn).
						AddProperty("time", tset)
					elts = append(elts, dmne)
					inde := NewIndomain(v.Name, dmn).
						AddProperty("time", tset)
					elts = append(elts, inde)
				}

			}
		} else if msg.Type == evs.DnsMessageType_response {
			for _, v := range msg.Answer {
				if v.Name != "" && v.Address != nil {
					addr := evs.AddressToString(v.Address)
					hoste := NewHostname(v.Name).
						AddProperty("time", tset)
					elts = append(elts, hoste)
					dnsqe := NewDnsresolve(v.Name, addr).
						AddProperty("time", tset)
					elts = append(elts, dnsqe)
				}

				dmn := ExtractDomain(v.Name)

				if dmn != "" {
					dmne := NewDomain(dmn).
						AddProperty("time", tset)
					elts = append(elts, dmne)
					inde := NewIndomain(v.Name, dmn).
						AddProperty("time", tset)
					elts = append(elts, inde)
				}

			}
		}

	case *evs.Event_HttpRequest:

		msg := ev.GetHttpRequest()
		host := msg.Header["Host"]
		ua := msg.Header["User-Agent"]

		if host != "" {

			servere := NewServer(host).
				AddProperty("time", tset)
			elts = append(elts, servere)

			requestse := NewRequests(sip, host).
				AddProperty("time", tset)
			elts = append(elts, requestse)

			servese := NewServes(dip, host).
				AddProperty("time", tset)
			elts = append(elts, servese)

		}

		if ua != "" {
			uae := NewUseragent(ua).
				AddProperty("time", tset)
			elts = append(elts, uae)

			usesagent := NewUses(sip, ua).
				AddProperty("time", tset)
			elts = append(elts, usesagent)
		}

	}

	return elts, nil

}

/*
func DescribeThreatGraph(e dt.Event) (interface{}, error) {

	s := NewSummary()

	res, tm, _ := DescribeThreatElements(e)
	for _, v := range res {
		v.Update(&s, tm)
	}

	g, _ := s.ToGraph()

	return g, nil

}
*/
