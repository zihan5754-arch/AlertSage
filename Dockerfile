FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY alertsage ./alertsage
COPY app ./app

# 只装运行必需的可选依赖（HTTP 层）
RUN pip install --upgrade pip && pip install ".[api]"

# 非 root 运行
RUN useradd --create-home --shell /bin/bash alertsage \
    && chown -R alertsage:alertsage /app
USER alertsage

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2)"

CMD ["alertsage", "serve", "--host", "0.0.0.0", "--port", "8000", "--fastapi"]
