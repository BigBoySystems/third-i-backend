#!/bin/sh

set -x -e

cp -fv third-i-backend.py /usr/local/sbin/third-i-backend
cp -fv third-i-backend@.service /lib/systemd/system/
chmod 644 /lib/systemd/system/third-i-backend@.service
pipenv install --system --deploy
