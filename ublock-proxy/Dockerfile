# ubproxy — filtering transparent proxy
FROM python:3.12-slim

# UID fixe : les manifestes Kubernetes s'y réfèrent (runAsUser/fsGroup).
RUN adduser --system --group --uid 10001 --home /var/lib/ubproxy ubproxy

WORKDIR /opt/ubproxy
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY ubproxy/ ./ubproxy/
COPY filters/ ./filters/
COPY config.example.toml ./

ENV PYTHONUNBUFFERED=1 \
    XDG_STATE_HOME=/var/lib

# Filter lists and the local CA live here: mount a volume to keep them across
# restarts (and to keep one stable CA for every client that trusts it).
VOLUME /var/lib/ubproxy
RUN mkdir -p /var/lib/ubproxy && chown -R ubproxy:ubproxy /var/lib/ubproxy

USER ubproxy
EXPOSE 8080 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD python3 -c "import socket,sys; s=socket.create_connection(('127.0.0.1',8080),3); s.close()"

ENTRYPOINT ["python3", "-m", "ubproxy"]
CMD ["run"]
