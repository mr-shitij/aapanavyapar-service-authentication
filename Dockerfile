FROM golang:1.15.7-alpine3.13

RUN apk update -qq && apk add git && apk add --no-cache bash

WORKDIR /go/src/aapanavypar_service_authentication

ADD . .

RUN go mod download

RUN go build -o main ./server/main.go

RUN wget https://raw.githubusercontent.com/vishnubob/wait-for-it/55c54a5abdfb32637b563b28cc088314b162195e/wait-for-it.sh && chmod +x wait-for-it.sh


# CMD ["./main"]
