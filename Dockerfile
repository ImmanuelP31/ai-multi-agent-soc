FROM python:3.11 AS base

WORKDIR /app

COPY requirements-min.txt .
RUN pip install --no-cache-dir -r requirements-min.txt

COPY . .

FROM base AS test

COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

FROM base AS runtime

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
