FROM python:3.12-alpine
RUN mkdir /app
COPY main.py /app/main.py
CMD ["python", "/app/main.py"]