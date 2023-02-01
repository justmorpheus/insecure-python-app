FROM python:3.8-slim-buster
LABEL maintainer="Justmorpheus <namaste@securitydojo.co.in"
LABEL version="1.0"
LABEL description="This is insecure password manager for k8s labs @ securitydojo"
WORKDIR /python-docker

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
copy . .

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0", "--port=8000"]
