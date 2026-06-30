FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install build && python -m build --wheel

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /build/dist/*.whl .
RUN pip install deephunter*.whl && rm -f deephunter*.whl
ENTRYPOINT ["deephunter"]
CMD ["--help"]
