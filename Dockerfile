FROM rockylinux/rockylinux:8

ENV container=docker

RUN dnf update -y && \
  dnf install -y epel-release && \
  dnf clean all

RUN echo root:changeme@123 | chpasswd && \
  dnf makecache && \
  dnf install -y epel-release && \
  dnf install -y --enablerepo=epel \
  passwd \
  sudo \
  systemd \
  systemd-libs \
  apr apr-util \
  bash \
  bzip2 \
  curl \
  iproute \
  krb5-libs \
  less \
  libxml2 \
  libyaml \
  openldap \
  openssh \
  openssh-clients \
  openssh-server \
  sshpass \
  perl \
  readline \
  rsync \
  sed \
  tar \
  which \
  zip \
  zlib \
  libuuid \
  libevent \
  libzstd \
  libuv \
  iputils \
  net-tools \
  python3 \
  libicu \
  xerces-c \
  python3-psycopg2 \
  python3-psutil \
  python3-pyyaml \
  clang \
  llvm \
  llvm-libs

RUN --mount=type=secret,id=repo_token bash -c 'ls /run/secrets && curl -1Lf https://downloads.enterprisedb.com/$(cat /run/secrets/repo_token)/dev/setup.rpm.sh | sudo bash'
RUN dnf -y install \
  warehouse-pg-7 \
  edb-whpg7-pgfs \
  edb-whpg7-pgaa \
  edb-whpg7-pgvector \
  edb-whpg7-madlib

COPY gpinitsystem_config /tmp/
COPY hostfile_gpinitsystem /tmp/
COPY init_system.sh /tmp/

RUN echo "cdw" > /tmp/gpdb-hosts && \
  echo "/usr/local/lib" >> /etc/ld.so.conf && \
  echo "/usr/local/lib64" >> /etc/ld.so.conf && \
  ldconfig && \
  chmod 777 /tmp/gpinitsystem_config && \
  chmod 777 /tmp/hostfile_gpinitsystem && \
  chmod 777 /tmp/init_system.sh && \
  hostname > ~/orig_hostname && \
  /usr/sbin/groupadd gpadmin && \
  /usr/sbin/useradd  gpadmin -g gpadmin -G wheel && \
  setcap cap_net_raw+ep /usr/bin/ping && \
  echo "changeme@123"|passwd --stdin gpadmin && \
  echo "gpadmin        ALL=(ALL)       NOPASSWD: ALL" >> /etc/sudoers && \
  echo "root           ALL=(ALL)       NOPASSWD: ALL" >> /etc/sudoers && \
  echo "export MASTER_DATA_DIRECTORY=/data/master/gpseg-1" >> /home/gpadmin/.bashrc && \
  echo "source /usr/local/greenplum-db/greenplum_path.sh" >> /home/gpadmin/.bashrc && \
  ssh-keygen -A && \
  echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

USER gpadmin
ENV USER=gpadmin
WORKDIR /home/gpadmin

EXPOSE 5432 22

CMD ["bash","-c","/tmp/init_system.sh"]
