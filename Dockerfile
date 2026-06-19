FROM --platform=linux/amd64 node:12

# Create unprivileged user

RUN groupadd --system vulndesk && useradd --system --create-home --gid vulndesk vulndesk

WORKDIR /home/vulndesk
COPY ./package*.json /home/vulndesk
RUN chown vulndesk:vulndesk --recursive /home/vulndesk/

USER vulndesk
RUN npm install

USER root
COPY . /home/vulndesk/

RUN chown vulndesk:vulndesk --recursive .
USER vulndesk

CMD ["npm", "start", "--prefix", "/home/vulndesk"]
