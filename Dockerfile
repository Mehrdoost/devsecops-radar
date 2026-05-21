FROM python:3.12-slim AS builder
WORKDIR /app
RUN pip install --upgrade pip
COPY pyproject.toml .
RUN mkdir devsecops_radar && touch devsecops_radar/__init__.py
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