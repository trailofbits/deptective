FROM python:3.13

RUN apt-get update && apt install -y apt-file python3-setuptools && apt-file update && mkdir /deptective

COPY . /deptective/

WORKDIR /deptective

RUN pip install .

CMD deptective
