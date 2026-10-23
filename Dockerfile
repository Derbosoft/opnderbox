# OPNderbox en conteneur : docker compose up -d, puis suivre l'adresse affichée par « docker compose logs ».
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 990 --home-dir /var/lib/opnderbox --shell /usr/sbin/nologin opnderbox \
    && install -d -o opnderbox -g opnderbox -m 700 /etc/opnderbox /var/lib/opnderbox

COPY opnderbox/ /opt/opnderbox/
COPY opnsense/ /opt/opnderbox/opnsense/

ENV OPNDERBOX_PORT=8443 PYTHONUNBUFFERED=1
USER opnderbox
EXPOSE 8443
VOLUME ["/etc/opnderbox", "/var/lib/opnderbox"]
HEALTHCHECK --interval=60s --timeout=5s CMD python3 -c "import ssl,urllib.request as u; u.urlopen('https://127.0.0.1:8443/api/session', context=ssl._create_unverified_context(), timeout=4)" || exit 1
CMD ["python3", "/opt/opnderbox/server.py"]
