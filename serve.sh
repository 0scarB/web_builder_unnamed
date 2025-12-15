#!/bin/sh
python3 -m http.server -b localhost 8080 1>>serve.log 2>>serve.log &
