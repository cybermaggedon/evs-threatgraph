# `evs-threatgraph`

Eventstream analytic for Cyberprobe event streams.  Subscribes to Pulsar
for Cyberprobe events and produces Gaffer graph database events describing
threats observed on events.

## Getting Started

The target deployment product is a container engine.  The analytic expects
a Pulsar service to be running, along with a Gaffer service.

```
  docker run -d \
      -e PULSAR_BROKER=pulsar://<PULSAR-HOST>:6650 \
      -e GAFFER_URL=http://gaffer-threat:8080/rest/v2 \
      -p 8088:8088 \
      docker.io/cybermaggedon/evs-threatgraph:<VERSION>
```
      
### Prerequisites

You need to have a container deployment system e.g. Podman, Docker, Moby.

You need to have a Gaffer service running using the
[threat graph schema](gaffer/threatgraph-schema/schema.json).  See the
[run-gaffer](gaffer/run_gaffer) script to start a simple development stack
with the schema.

You also need a Pulsar exchange, being fed by events from Cyberprobe.

### Installing

The easiest way is to use the containers we publish to Docker hub.
See https://hub.docker.com/r/cybermaggedon/evs-threatgraph

```
  docker pull docker.io/cybermaggedon/evs-threatgraph:<VERSION>
```

If you want to build this yourself, you can just clone the Github repo,
and type `make`.

## Deployment configuration

The following environment variables are used to configure:

| Variable | Purpose | Default |
|----------|---------|---------|
| `INPUT` | Specifies the Pulsar topic to subscribe to.  This is just the topic part of the URL e.g. `cyberprobe`. | `ioc` |
| `METRICS_PORT` | Specifies the port number to serve Prometheus metrics on.  If not set, metrics will not be served. The container has a default setting of 8088. | `8088` |
| `GAFFER_URL` | Specifies the GAFFER REST v2 API. | `http://localhost:8080/rest/v2` |

