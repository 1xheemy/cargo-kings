# Use an official Node 18 image
FROM node:18

# Install build dependencies for native modules like better-sqlite3
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    build-essential \
    python3 \
    python3-dev \
    libsqlite3-dev \
    pkg-config \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files first to leverage Docker cache
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy app files
COPY . .

ENV NODE_ENV=production

# Expose default port (Railway will provide $PORT)
EXPOSE 3000

CMD ["npm", "start"]
