FROM ubuntu:latest

LABEL version="0.9"
LABEL maintainer="Ben Krueger <sayhello@blk8.de>"

RUN apt-get update
RUN apt-get install -y python3.9 python3-pip python3-psycopg2

RUN pip3 install Flask Werkzeug flask-sqlalchemy flask-login Flask-WTF email_validator flask_wtf flask-sitemap Flask-Mail flask-restx flask-marshmallow marshmallow-sqlalchemy markdown2 boto3 mkdocs waitress

RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/false cpeman

EXPOSE 5020

USER cpeman

RUN mkdir /home/cpeman/templates /home/cpeman/static /home/cpeman/uploads /home/cpeman/downloads /home/cpeman/.aws

COPY *.py *.sh *.yml /home/cpeman/
COPY templates/ /home/cpeman/templates/
COPY static/ /home/cpeman/static/
COPY docs/ /home/cpeman/docs/

RUN cd /home/cpeman && mkdocs build

CMD ["/home/cpeman/flask.sh"]
