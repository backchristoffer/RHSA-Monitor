FROM golang:bullseye
WORKDIR /app
COPY . .
RUN go build .
CMD [ "./rhsa-monitor" ]