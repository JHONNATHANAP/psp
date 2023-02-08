FROM python:3.9.6

COPY . ./app
RUN pip install -r /app/requirements.txt

EXPOSE 5001
CMD ["python", "/src/app.py"]