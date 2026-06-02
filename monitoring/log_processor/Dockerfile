FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# HoneyMind src is mounted at /honeymind_src at runtime via docker-compose volume
ENV PYTHONPATH="/app:/honeymind_src"
ENTRYPOINT ["python", "-u", "main.py"]
