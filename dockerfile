FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk --no-cache upgrade

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir pymongo

# бекенд
COPY main.py /app/

# уся фронт-статика (index.html, message.html, error.html, style.css, logo.png тощо)
COPY front-init/ /app/front-init/

EXPOSE 3000 5000
CMD ["python", "main.py"]