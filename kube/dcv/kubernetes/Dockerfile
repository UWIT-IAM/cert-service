FROM python:latest

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt

CMD ["python", "-m", "src.autorenew"]
