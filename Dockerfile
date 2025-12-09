FROM python:3.12-slim

WORKDIR /app
COPY demo/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY demo/ .

EXPOSE 8081
CMD ["python", "app.py"]
