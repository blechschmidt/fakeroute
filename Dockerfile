FROM python:3-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ARG SOURCE=.

WORKDIR /app
COPY ${SOURCE} .
RUN uv sync --locked --no-dev

ENTRYPOINT ["uv", "run", "fakeroute"]
