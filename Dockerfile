FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .
COPY alembic.ini ./
COPY migrations ./migrations
COPY examples ./examples
RUN useradd --system --uid 10001 shadow && chown -R shadow:shadow /app
USER shadow
CMD ["sh", "-c", "shadow-ai migrate && shadow-ai serve"]
