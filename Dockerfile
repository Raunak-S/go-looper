FROM golang:1.16-alpine

COPY . /app
WORKDIR /app
RUN go mod init go-looper
RUN go build -o main main.go

CMD ["main"]