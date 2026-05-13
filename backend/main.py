from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"message": "AI SOC Backend Running"}

import redis

redis_client = redis.Redis(host="redis", port=6379, decode_responses=True)

@app.get("/redis-test")
def redis_test():
    redis_client.set("status", "Redis Connected")
    value = redis_client.get("status")
    return {"redis_message": value}