FROM python:3.12-slim AS builder
RUN pip install --upgrade pip
COPY pyproject.toml .
RUN pip install --user --no-cache-dir -e .

FROM python:3.12-slim
RUN useradd -m -u 1000 pipeline && mkdir /app && chown pipeline /app
WORKDIR /app
COPY --from=builder /root/.local /home/pipeline/.local
COPY . .
RUN chown -R pipeline /app
ENV PATH="/home/pipeline/.local/bin:$PATH"
USER pipeline
EXPOSE 8080
CMD ["python", "-m", "devsecops_radar.web.app"]