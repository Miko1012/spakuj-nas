FROM python:3.7-alpine
WORKDIR /app
ADD app.py .
ADD requirements.txt .
RUN python -m pip install -r requirements.txt

CMD ["python", "app.py"]
