FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# HoneyMind src is mounted at /honeymind_src at runtime via docker-compose volume
# Include subdirs so bare imports (e.g. `from attack_classifier import ...`) work
ENV PYTHONPATH="/app:/honeymind_src:/honeymind_src/analysis:/honeymind_src/logging_pipeline"
ENTRYPOINT ["python", "-u", "main.py"]
