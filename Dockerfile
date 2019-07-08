FROM node:8.10

WORKDIR /app
ADD package.json .
ADD package-lock.json .
RUN npm install

ADD connection-profile.yaml .
ADD channel channel 
ADD chaincode chaincode

ARG FABRIC_HOST=localhost
RUN sed --in-place=.backup s/localhost/$FABRIC_HOST/ connection-profile.yaml

ADD app.js .

ENV PORT 8080

RUN mkdir /data

ENTRYPOINT ["node", "app.js"]
