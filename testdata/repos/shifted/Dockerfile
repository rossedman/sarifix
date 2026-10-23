FROM alpine:3.18
# Fixture: same findings as basic, with the lines below
# shifted down two.
RUN apk add curl
COPY app /app
ENTRYPOINT ["/app"]
