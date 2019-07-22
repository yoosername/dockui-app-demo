FROM node:alpine
ADD . /app
WORKDIR /app
RUN npm install
RUN npm -g install nodemon
CMD ["nodemon", "./server.js"]