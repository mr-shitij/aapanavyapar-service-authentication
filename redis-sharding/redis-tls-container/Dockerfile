FROM redis:6.2

WORKDIR /

RUN mkdir /usr/local/etc/redis

COPY redis.conf /usr/local/etc/redis/

ENTRYPOINT ["tail", "-f", "/dev/null"]