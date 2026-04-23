FROM python:3.14.3-slim-bookworm AS base
WORKDIR /app

COPY flag.txt .
COPY server.py .
COPY tinymt32.py .

FROM pwn.red/jail
COPY --from=base / /srv

RUN echo -e "#!/bin/sh\npython3 server.py" > /srv/app/run && chmod 555 /srv/app/run
ENV JAIL_TIME=120 JAIL_MEM=100M JAIL_CPU=100 JAIL_POW=7500