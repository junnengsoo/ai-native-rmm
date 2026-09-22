FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY control_plane ./control_plane
COPY alembic.ini .
COPY migrations ./migrations
USER 65534:65534
CMD ["python", "-m", "uvicorn", "control_plane.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--log-level", "warning", "--ws-max-size", "300000", "--limit-concurrency", "256"]
