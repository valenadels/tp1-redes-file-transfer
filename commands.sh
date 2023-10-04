#!/bin/bash

# start server
python3 start-server.py -s server-storage -v

# upload selective repeat
python3 upload.py -v -s test-files/image.jpg -pr sr

# upload stop and wait
python3 upload.py -v -s test-files/image.jpg

# download selective repeat
python3 download.py -v -d imagen.jpg -pr sr -n image.jpg

# download stop and wait
python3 download.py -v -d imagen.jpg -n image.jpg