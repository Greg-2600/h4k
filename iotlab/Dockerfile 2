# h4k IoT/OT lab — simulated MQTT broker, Modbus PLC, CoAP/SSDP/BACnet/SNMP
# devices, RTSP camera and a device admin page. Nothing here is real hardware.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /opt/iotlab
COPY simulator.py /opt/iotlab/simulator.py

# Ports are documented rather than published; compose uses host networking for
# the lab so the h4k container can reach 127.0.0.1:<port>.
EXPOSE 1883 502 5683/udp 1900/udp 47808/udp 161/udp 554 8080

HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
  CMD IOT_HEALTH=1 python3 /opt/iotlab/simulator.py | grep -q '"ok"' || exit 1

ENTRYPOINT ["python3", "/opt/iotlab/simulator.py"]
