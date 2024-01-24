FROM ubuntu:jammy AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && apt-get install -y gcc linux-headers-generic python3
COPY apt-strace.c /
RUN gcc apt-strace.c -Wall -Wextra -Werror -o apt-strace

FROM ubuntu:jammy
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update
RUN echo "APT::Get::Install-Recommends \"false\";" >> /etc/apt/apt.conf
RUN echo "APT::Get::Install-Suggests \"false\";" >> /etc/apt/apt.conf
RUN mkdir /src/
COPY --from=builder /apt-strace /usr/bin/

ENTRYPOINT ["/usr/bin/apt-strace"]
