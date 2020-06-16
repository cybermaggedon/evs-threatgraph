
FROM fedora:32

COPY evs-threatgraph /usr/local/bin/

ENV PULSAR_BROKER=pulsar://exchange:6650
ENV METRICS_PORT=8088

EXPOSE 8088

CMD /usr/local/bin/evs-threatgraph

