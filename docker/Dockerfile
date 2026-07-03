FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE /app/
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.txt
COPY . /app
RUN python -m pip install -e .
EXPOSE 8080
CMD ["python", "-m", "sbomops.workbench.server", "--host", "0.0.0.0", "--port", "8080"]
