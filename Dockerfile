FROM python:3.8.10-alpine

#RUN useradd --create-home --shell /bin/bash app_user
RUN adduser --home /home/app_user --disabled-password --shell /bin/bash app_user

WORKDIR /home/app_user

RUN pip freeze > requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

USER app_user

COPY --chown=app_user:app_user . .

CMD ["/bin/sh"]
