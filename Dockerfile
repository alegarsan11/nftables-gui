FROM python
LABEL org.opencontainers.image.source=https://github.com/DZ-IO/nftables-gui
LABEL org.opencontainers.image.description="This is a repository to develop a web interface to enble configuration of nftables via GUI. (with docker support)"
LABEL org.opencontainers.image.licenses=GPLV3
COPY . /opt/app
WORKDIR /opt/app/nftables-frontend
RUN pip install \
gunicorn \
flask==3.0.1 \
flask-bootstrap==3.3.7.1 \
flask_sqlalchemy==3.1.1 \
flask-migrate==4.0.7 \
flask-login==0.6.3 \
flask-wtf==1.2.1 \
email_validator \
matplotlib \
python-Levenshtein requests \
&& apt-get update && apt-get install -y nftables \
python3-hug \
python3-nftables \
&& rm -rf /var/cache/* /var/log/* /tmp/*

VOLUME ["/opt/app/nftables-frontend/instance","/opt/app/nftables-frontend/static/img"]

ENTRYPOINT  ["/usr/local/bin/gunicorn","-c","gunicorn.conf.py"]