# Fleet host under test. BASE can be any Alpine-based image (override if Docker Hub is rate-limited).
ARG BASE=alpine:3.20
FROM ${BASE}
USER root
RUN apk add --no-cache openssh-server \
 && ssh-keygen -A \
 && sed -i 's/^root:!:/root:*:/' /etc/shadow
COPY sshd_config /etc/ssh/sshd_config
EXPOSE 22
ENTRYPOINT []
CMD ["/usr/sbin/sshd", "-D", "-e"]
