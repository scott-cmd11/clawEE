FROM mcr.microsoft.com/playwright:v1.51.1-noble
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev || npm install

COPY server.mjs ./
RUN mkdir -p /data/vdi-artifacts

ENV PORT=8091
ENV VDI_CONTAINER_ARTIFACT_PATH=/data/vdi-artifacts

EXPOSE 8091
CMD ["node", "server.mjs"]
