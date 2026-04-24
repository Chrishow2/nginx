FROM docker:27-cli AS dockercli

FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends certbot dnsutils python3-certbot-dns-cloudflare \
    && rm -rf /var/lib/apt/lists/*

COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.mjs ./
COPY hooks ./hooks
RUN sed -i 's/\r$//' hooks/*.sh && chmod +x hooks/dns-auth.sh hooks/dns-cleanup.sh
COPY public ./public

ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "server.mjs"]
