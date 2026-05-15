# Stage 1: Build dependencies
FROM python:3.12-slim as builder
RUN pip install --upgrade pip
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Production image
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