FROM golang:1.16-alpine as build

COPY /src /app
WORKDIR /app
ENV CGO_ENABLED=0
RUN go build -o main 

#CMD ["go", "run", "main.go", "1", "1", "c"]
FROM scratch
COPY --from=build /app/main /
ENTRYPOINT ["./main", "1", "1", "c"]