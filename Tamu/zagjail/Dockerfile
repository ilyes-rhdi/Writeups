FROM debian@sha256:1d3c811171a08a5adaa4a163fbafd96b61b87aa871bbc7aa15431ac275d3d430 AS base

RUN apt-get update -y; apt-get install build-essential git python3 -y

RUN git clone https://github.com/macsencasaus/zag.git
WORKDIR /zag

RUN git checkout 3c52893
RUN ./build.sh

FROM pwn.red/jail

COPY --from=base / /srv

RUN mkdir -p /srv/app
COPY --from=base /zag/build/release/zag /srv/app/zag
RUN chmod 755 /srv/app/zag
COPY server.py /srv/app/server.py
COPY flag.txt /srv/app/flag.txt

RUN echo -e "#!/bin/sh\npython3 server.py" > /srv/app/run && chmod 555 /srv/app/run
ENV JAIL_TIME=120 JAIL_PIDS=100 JAIL_MEM=300M JAIL_CPU=300 JAIL_TMP_SIZE=100M JAIL_ENV_CC=/usr/bin/cc JAIL_ENV_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin