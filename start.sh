#!/bin/bash

# Spustenie screen session pre emailov
screen -dmS emails python3 emaillistener.py

# Spustenie screen session pre webtesco
screen -dmS webtesco gunicorn -w 4 -b 0.0.0.0:8000 app:app

echo "Obe screen sessions boli spustené."
