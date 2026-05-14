FROM python:3.11

WORKDIR /app

COPY requirements-min.txt .
RUN pip install --no-cache-dir -r requirements-min.txt

COPY . .

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]