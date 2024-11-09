FROM python:3.11

RUN apt-get update && apt install -y apt-file python3-setuptools && apt-file update && mkdir /deptective

COPY . /apt_trace/

WORKDIR /apt_trace

RUN pip install .

CMD apt-trace
