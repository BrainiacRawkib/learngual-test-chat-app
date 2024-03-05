FROM python:3.11.5

ENV DEBIAN_FRONTEND=noninteractive

ENV PYTHONUNBUFFERED=1

ENV ENVIRONMENT=prod

RUN pip install --upgrade pip

# set the working directory
WORKDIR /app

# install dependencies
COPY ./requirements /app/requirements
RUN pip install --no-cache-dir -r /app/requirements/base.txt

COPY . /app

RUN python manage.py migrate

CMD ["python", "manage.py", "runserver", "8004"]
