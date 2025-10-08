FROM python:3.14-alpine
RUN mkdir /app
WORKDIR /app
COPY main.py /app/main.py
COPY requirements.txt /app/requirements.txt

RUN pip install -r requirements.txt

CMD ["python", "/app/main.py"]