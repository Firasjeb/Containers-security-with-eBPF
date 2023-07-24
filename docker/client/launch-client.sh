#bin/bash
docker run --name client -it --rm -p 8080:80 -p 43:443 client-image
