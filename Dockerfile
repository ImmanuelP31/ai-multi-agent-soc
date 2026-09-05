FROM python:3.11.16-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84 AS python-base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120

RUN groupadd --gid 10001 soc && \
    useradd --uid 10001 --gid soc --create-home --shell /usr/sbin/nologin soc

WORKDIR /app
COPY requirements*.txt ./

FROM python-base AS runtime-deps
RUN pip install --no-cache-dir -r requirements-runtime.txt

FROM runtime-deps AS runtime

COPY --chown=soc:soc . .
RUN mkdir -p /app/logs && chown -R soc:soc /app/logs
USER soc

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM runtime-deps AS sequence-runtime

RUN pip install --no-cache-dir -r requirements-sequence.txt
COPY --chown=soc:soc . .
RUN mkdir -p /app/logs && chown -R soc:soc /app/logs
USER soc

CMD ["python", "agents/investigation_agent.py"]

FROM runtime-deps AS test

RUN pip install --no-cache-dir -r requirements-dev.txt
COPY --chown=soc:soc . .
RUN mkdir -p /app/logs && chown -R soc:soc /app/logs
USER soc

CMD ["python", "-m", "pytest"]

FROM runtime-deps AS training

RUN pip install --no-cache-dir -r requirements-training.txt
COPY --chown=soc:soc . .
RUN mkdir -p /app/logs && chown -R soc:soc /app/logs
USER soc

CMD ["python", "ml/training/train_anomaly_model.py"]
