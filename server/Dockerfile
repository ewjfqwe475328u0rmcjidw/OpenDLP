FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 leakwarden
WORKDIR /app
COPY server/requirements.txt /app/server/requirements.txt
RUN pip install --no-cache-dir -r /app/server/requirements.txt
COPY server /app/server
COPY policies /app/policies
RUN mkdir -p /data && chown leakwarden /data /app/policies
ENV LEAKWARDEN_DB=/data/leakwarden.db LEAKWARDEN_POLICY=/app/policies/default-policy.json
USER leakwarden
WORKDIR /app/server
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
