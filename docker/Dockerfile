FROM python:3.12-slim AS base
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

FROM base AS runtime
COPY platformkit /deps/platformkit
COPY reviewgate /app
WORKDIR /app
RUN pip install --no-cache-dir "/deps/platformkit[postgres,redis]" \
    && pip install --no-cache-dir ".[postgres]"
EXPOSE 8092
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8092/health')"
CMD ["reviewgate", "serve", "--host", "0.0.0.0", "--port", "8092"]

FROM runtime AS test
RUN pip install --no-cache-dir ".[dev]"
CMD ["pytest", "tests/", "-v"]
