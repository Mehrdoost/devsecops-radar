FROM python:3.12-slim

WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project and install it
COPY . .
RUN pip install -e .

# Create a directory for the database and set as volume
RUN mkdir /data
VOLUME /data
ENV FINDINGS_FILE=/data/findings.json

EXPOSE 8080

CMD ["python", "-m", "devsecops_radar.web.app"]