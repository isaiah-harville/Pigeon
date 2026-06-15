# site

Static marketing and privacy-policy site for Pigeon.

## Local Preview

Open `index.html` directly, or serve the directory with any static file server.

## Container

```sh
docker build -f deploy/Dockerfile -t pigeon-website .
docker run --rm -p 8080:8080 pigeon-website
```
