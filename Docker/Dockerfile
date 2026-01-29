# syntax=docker/dockerfile:1.4

## You can change these variables
ARG COLLAB_SERVER="XXXXXXXXXX"
ARG XSS_SERVER="XXXXXXXXXXX"
ARG SHODAN_API_KEY="XXXXXXXXXXXXXX"

ARG LANG=en_US.UTF-8
ARG LANGUAGE=en_US

##################################################
###> Do NOT change anything beyond this point <###
##################################################

FROM ubuntu:latest AS base

LABEL org.label-schema.name='reconftw'
LABEL org.label-schema.description='A simple script for full recon'
LABEL org.label-schema.usage='https://github.com/six2dez/reconftw'
LABEL org.label-schema.url='https://github.com/six2dez/reconftw'
LABEL org.label-schema.docker.cmd.devel='docker run --rm -ti six2dez/reconftw'
LABEL MAINTAINER="six2dez"

ARG COLLAB_SERVER
ARG XSS_SERVER
ARG SHODAN_API_KEY

ARG LANG
ARG LANGUAGE

ARG GIT_REPOSITORY_AXIOM="https://github.com/attacksurge/ax.git"
ARG GIT_REPOSITORY_RECONFTW="https://github.com/six2dez/reconftw"
ARG INSTALL_AXIOM=true

ENV COLLAB_SERVER=$COLLAB_SERVER
ENV XSS_SERVER=$XSS_SERVER
ENV SHODAN_API_KEY=$SHODAN_API_KEY

ENV LANG=$LANG
ENV LANGUAGE=$LANGUAGE
ENV LC_ALL=$LANG

ENV GIT_REPOSITORY_AXIOM=$GIT_REPOSITORY_AXIOM
ENV GIT_REPOSITORY_RECONFTW=$GIT_REPOSITORY_RECONFTW

ENV INSTALL_AXIOM=$INSTALL_AXIOM

ENV DEBIAN_FRONTEND=noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN=true

ENV GOROOT='/usr/local/go'
ENV GOPATH='/root/go'
ENV AXIOMPATH='/root/.axiom/interact'
ENV CARGOPATH='/root/.cargo/bin'
ENV PATH="${GOROOT}/bin:${GOPATH}/bin:${AXIOMPATH}:${CARGOPATH}:${PATH}"

SHELL [ "/bin/bash", "-c" ]

COPY 01_nodoc /etc/dpkg/dpkg.cfg.d/

RUN <<eot
#!/bin/bash
set -euxo pipefail

###>> Backup .bashrc <<###
cp /root/.bashrc /root/original.bashrc

###>> System Configuration <<###
apt clean all
apt update
apt full-upgrade -f -y --allow-downgrades
apt install -y --no-install-recommends apt-utils ca-certificates curl git lsb-release nano wget vim jq htop net-tools dnsutils nmap python3 python3-pip unzip whois

###>> Congifure Locales <<###
apt install -y --no-install-recommends locales
sed -i -- "/${LANG}/s/^# //g" /etc/locale.gen
dpkg-reconfigure locales
update-locale LANG=${LANG}

###>> Congifure localepurge <<###
apt install -y --no-install-recommends localepurge
sed -i -- '/^USE_DPKG/s/^/#/' /etc/locale.nopurge
dpkg-reconfigure localepurge
localepurge

###>> Configure Axiom <<###
if [ "${INSTALL_AXIOM}" = "true" ]; then
    mkdir -p /root/.axiom/
    git clone ${GIT_REPOSITORY_AXIOM} /root/.axiom/
    cd /root/.axiom/interact
    ./axiom-configure --unattended --shell Bash || echo "Axiom configure failed or was skipped; continue without cloud fleet."
    ## This avoids useless error messages later.
    touch /root/.axiom/axiom.json
    touch /root/.axiom/interact/includes/functions.sh
else
    echo "INSTALL_AXIOM=${INSTALL_AXIOM}; skipping Axiom tooling."
fi

###>> Install reconFTW <<###
mkdir -p /root/Tools
mkdir -p /reconftw
git clone ${GIT_REPOSITORY_RECONFTW} /reconftw
cd /reconftw
sh -c 'echo 1 | ./install.sh'

###>> Restore .bashrc <<###
mv /root/original.bashrc /root/.bashrc
find /root -type f \( -name '.bashrc*' -not -name '.bashrc' \) -delete

###>> Clean up <<###
apt update
apt remove --purge -y build-essential
apt autoremove -y
apt clean all
find /var/lib/apt/lists -type f -delete
find /var/cache -type f -delete
find /var/log -type f -delete
find /tmp -type f -delete
rm -rf /root/.cache
rm -rf /root/go
eot

COPY github_tokens.txt /root/Tools/.github_tokens
COPY notify.conf /root/.config/notify/provider-config.yaml

###>> Configure Axiom Provider <<###
RUN <<eot
#!/bin/bash
set -euxo pipefail
if [ "${INSTALL_AXIOM}" = "true" ]; then
    ###>> Regenerate SSH Keys <<###
    apt update && apt install -y --no-install-recommends openssh-client

    mkdir -p /root/.ssh
    mkdir -p /root/.axiom/configs

    ssh-keygen -b 2048 -t rsa -f /root/.ssh/axiom_rsa -q -N ""
    cat /root/.ssh/axiom_rsa.pub > /root/.axiom/configs/authorized_keys

    apt remove --purge -y openssh-client && apt autoremove -y && apt clean all
    find /var/lib/apt/lists -type f -delete
    find /var/cache -type f -delete
    find /var/log -type f -delete
    find /tmp -type f -delete
    rm -rf /root/.cache
else
    echo "INSTALL_AXIOM=${INSTALL_AXIOM}; skipping Axiom provider setup."
fi
eot

#COPY axiom-config.ini /root/.axiom/configs/config.ini
#COPY axiom-custom-provider.json /root/.axiom/accounts/personal.json
RUN if [ "${INSTALL_AXIOM}" = "true" ]; then axiom-account personal || echo "Axiom account not configured; provide provider config to enable it."; fi
# RUN az group delete --name axiom --yes --no-wait

 # This command exits with return code 1, so leave the '|| :' or the build will fail.
# COPY axiom-custom-provider.json /root/.axiom/accounts/personal.json
RUN if [ "${INSTALL_AXIOM}" = "true" ]; then axiom-build reconftw || :; fi

## Issue 271
EXPOSE 85-90

WORKDIR /reconftw

ENTRYPOINT [ "./reconftw.sh" ]
CMD [ "--help" ]
