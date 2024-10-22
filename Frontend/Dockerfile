FROM node:lts

EXPOSE 5173

RUN apk add --no-cache mc


WORKDIR /app

COPY ./secure-notes-react /app

RUN npm install

CMD ["npm", "run", "dev"]