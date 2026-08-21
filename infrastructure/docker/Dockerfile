FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 hobbit
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER hobbit
EXPOSE 8000
CMD ["uvicorn","src.api.server:app","--host","0.0.0.0","--port","8000"]
