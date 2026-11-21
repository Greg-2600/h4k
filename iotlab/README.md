# h4k IoT/OT lab

A single fake device that speaks the protocols the IoT/OT pack probes. It exists
so the demo never depends on a real PLC, camera or broker — and so a defender can
see what normal discovery looks like on the wire.

| Protocol | Port | Behaviour |
|---|---|---|
| MQTT 3.1.1 | TCP 1883 | CONNECT/CONNACK, SUBSCRIBE/SUBACK, PING, PUBLISH logging |
| Modbus/TCP | TCP 502 | FC1/3/4 reads, FC5/6/15/16 acknowledge writes and mutate in-memory state |
| CoAP | UDP 5683 | `/.well-known/core` resource list |
| SSDP/UPnP | UDP 1900 | M-SEARCH response with SERVER/USN/LOCATION |
| BACnet | UDP 47808 | Who-Is → I-Am (device 1234, vendor 999) |
| SNMPv2c | UDP 161 | `sysDescr.0` → "h4k-iotlab simulated PLC" |
| RTSP | TCP 554 | OPTIONS/DESCRIBE with `Server: h4k-iotlab-cam/1.0` |
| HTTP | TCP 8080 | Device admin page (`<title>h4k IoT lab device</title>`) |

## Run

```sh
docker compose -f h4k/docker-compose.yml --profile iotlab up -d iotlab
```

The compose service uses host networking, so from h4k (Linux host):

```sh
curl -s -X POST localhost:3137/api/lab/iot/discover \
  -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1"}'
```

## Verified

Built as `h4k-iotlab:latest`; TCP MQTT/Modbus/RTSP/HTTP probes work through a
published-port container. UDP probes (CoAP/SSDP/BACnet/SNMP) work inside the
container and with host networking; Docker Desktop/colima port publishing for
UDP can silently drop replies, so prefer host networking on the lab host.

## Safety

The Modbus writes only change a Python list in this container. There is no
fieldbus, no serial line, and no physical device. All other probes are reads.
Use it only on a lab network you control.
