FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY changeradar.py feeds.py server.py inventory.yaml ./
COPY events ./events
COPY static ./static
RUN useradd -r -u 10001 cr && mkdir /data && chown cr /data
USER cr
ENV CR_DATA=/data CR_HOST=0.0.0.0 CR_PORT=8080 PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8080
CMD ["python", "server.py"]
