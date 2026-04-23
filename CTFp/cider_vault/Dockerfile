FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY cider_vault ./cider_vault
COPY ld-linux-x86-64.so.2 ./ld-linux-x86-64.so.2
COPY libc.so.6 ./libc.so.6
COPY flag.txt ./flag.txt
COPY run.sh ./run.sh
RUN chmod 555 /app/cider_vault /app/run.sh /app/ld-linux-x86-64.so.2 && chmod 444 /app/libc.so.6 /app/flag.txt
EXPOSE 1337
CMD ["./run.sh"]
