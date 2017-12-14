FROM ubuntu

MAINTAINER JohnMenerick version .9
##John Menerick https://securesql.info

ADD VERSION .
RUN apt-get update && apt-get install -y --no-install-recommends git python-pip && apt-get autoremove && apt-get autoclean && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/cloudsriseup/PoorOperationalSecurityPractices
RUN cd PoorOperationalSecurityPractices && pip install -r requirements.txt && python pooropssec.py
