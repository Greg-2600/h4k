# h4k telemetry agent — tail logs and ship JSON events to the h4k API.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/telemetry
COPY agent.py /opt/telemetry/agent.py

# Run as a non-root user; the mounted log directory only needs read access.
RUN useradd --create-home --shell /usr/sbin/nologin agent
USER agent

ENTRYPOINT ["python3", "/opt/telemetry/agent.py"]
