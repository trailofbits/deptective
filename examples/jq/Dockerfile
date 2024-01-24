FROM trailofbits/apt-strace

RUN mkdir /apt_trace

WORKDIR /apt_trace

RUN apt-get install -y git autoconf automake libtool && git clone https://github.com/stedolan/jq.git && cd jq && autoreconf -i

WORKDIR /apt_trace/jq

# RUN apt-strace ./configure --auto
