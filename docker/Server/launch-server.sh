#!/bin/bash

docker run  --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined  --name container1 -d -p 443:443 -p 80:80 -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf -v $(pwd)/ssl:/etc/nginx/ssl -v /home/firas/nginx-1.21.4/html:/usr/share/nginx/html -v $(pwd)/programs:/programs  nginx-image


docker logs $(docker ps -a -q)

docker exec -it container1 /bin/bash
