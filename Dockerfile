FROM python:3.11

WORKDIR /app

COPY . .

RUN pip install fastapi uvicorn sqlalchemy psycopg2-binary redis

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
