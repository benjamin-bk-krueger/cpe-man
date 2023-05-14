#!/bin/sh
. ~/.profile
echo "Starting..."

# Stop server
killall /home/cpeman/venv/bin/python3

# Pull current GIT repo
cd /home/cpeman/git/cpe-man/
git pull

# Purge and copy files to target folders
rm -rf /home/cpeman/templates/*
rm -rf /home/cpeman/static/*
rm -rf /home/cpeman/docs/*

cp -v *.py *.sh *.yml /home/cpeman/
cp -v templates/* /home/cpeman/templates/
cp -v static/* /home/cpeman/static/
cp -vr docs/* /home/cpeman/docs/
git log -1 > /home/cpeman/gitlog.txt

# Update mkdocs files
cd /home/cpeman/
mkdocs build

# Start server
nohup ./flask.sh >/dev/null 2>&1 &
sleep 5
echo "Finished."
