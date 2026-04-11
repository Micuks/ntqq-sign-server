FROM debian:bookworm-slim

RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && apt-get install -y --no-install-recommends \
    python3 gcc libc6-dev ca-certificates curl \
    libgnutls30 libglib2.0-0 libnss3 libatk1.0-0 libcups2 \
    libdrm2 libgbm1 libxkbcommon0 libpango-1.0-0 libcairo2 \
    libvips42 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Download and extract QQ Linux — specify version via build arg
ARG QQ_DEB_URL=https://dldir1.qq.com/qqfile/qq/QQNT/Linux/QQ_3.2.15_250116_amd64_01.deb
RUN curl -fsSL -o /tmp/qq.deb "${QQ_DEB_URL}" && \
    dpkg -x /tmp/qq.deb /tmp/qq && \
    cp /tmp/qq/opt/QQ/resources/app/wrapper.node /app/ && \
    cp /tmp/qq/opt/QQ/resources/app/package.json /app/ && \
    cp /tmp/qq/opt/QQ/resources/app/sharp-lib/libvips-cpp.so.42 /app/ 2>/dev/null || true && \
    cp /tmp/qq/opt/QQ/resources/app/libbugly.so /app/ 2>/dev/null || true && \
    cp /tmp/qq/opt/QQ/resources/app/libcrbase.so /app/ 2>/dev/null || true && \
    rm -rf /tmp/qq /tmp/qq.deb

COPY symbols.c /app/
RUN gcc -std=c99 -shared -fPIC -o /app/libsymbols.so /app/symbols.c

COPY sign.py /app/

ENV LD_LIBRARY_PATH=/app

EXPOSE 8080

CMD ["python3", "/app/sign.py", "--wrapper", "/app/wrapper.node", "--host", "0.0.0.0", "--port", "8080"]
