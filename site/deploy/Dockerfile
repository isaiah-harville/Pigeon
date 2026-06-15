FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY deploy/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY index.html styles.css /usr/share/nginx/html/
COPY assets /usr/share/nginx/html/assets
COPY privacy-policy /usr/share/nginx/html/privacy-policy
COPY support /usr/share/nginx/html/support

EXPOSE 8080
