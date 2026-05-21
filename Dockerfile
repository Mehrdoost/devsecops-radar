FROM python:3.12-slim

RUN useradd -m -u 1000 pipeline && mkdir /app && chown pipeline /app
WORKDIR /app
COPY pyproject.toml .
COPY devsecops_radar devsecops_radar
RUN pip install --no-cache-dir -e .
RUN chown -R pipeline /app

USER pipeline
EXPOSE 8080
CMD ["python", "-m", "devsecops_radar.web.app"]