FROM python:3.9

RUN apt-get update && apt install -y apt-file python3-setuptools && apt-file update && mkdir /apt_trace

COPY . /apt_trace/

WORKDIR /apt_trace

RUN pip install .

CMD apt-trace
