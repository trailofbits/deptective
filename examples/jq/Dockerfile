FROM trailofbits/apt-trace AS PREBUILD

WORKDIR /apt_trace

RUN apt-get update && apt-get install -y git autoconf automake libtool && git clone https://github.com/stedolan/jq.git && cd jq && autoreconf -i

FROM trailofbits/apt-trace

COPY --from=PREBUILD /apt_trace /

WORKDIR /apt_trace/jq

ENTRYPOINT ["apt-trace", "./configure", "--auto"]
