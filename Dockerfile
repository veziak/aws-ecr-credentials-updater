FROM python:3.12-alpine
RUN mkdir /app
COPY main.py /app/main.py
COPY requirements.txt /app/requirements.txt

RUN pip install -r requirements.txt

CMD ["python", "/app/main.py"]