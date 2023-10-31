FROM node:18
WORKDIR /server
COPY package.json .
COPY Dockerfile .
COPY . .
RUN npm install
CMD npm start