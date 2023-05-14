#!/bin/bash
sudo -i -u postgres
createuser --interactive
createdb flask

su - flask -s /bin/bash 
psql
ALTER USER flask PASSWORD 'password';
\q


pg_dump -F c cpeman > cpeman.dump
pg_restore -d cpeman cpeman.dump
pg_restore -U cpeman -d cpeman tmp/cpeman.dump
