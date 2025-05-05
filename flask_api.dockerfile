FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir gunicorn eventlet     # <- ensures WS support

COPY . .

EXPOSE 5001

CMD ["gunicorn", "-k", "eventlet", "-w", "4",
    "-b", "0.0.0.0:5001", "mtaa_backend:app"]