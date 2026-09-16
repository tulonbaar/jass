FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose the web server port
EXPOSE 8080

CMD ["python", "run.py", "--serve", "--host-bind", "0.0.0.0"]
