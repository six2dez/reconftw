# syntax=docker/dockerfile:1.4

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

## You can change these variables
ARG COLLAB_SERVER="XXXXXXXXXX"
ARG XSS_SERVER="XXXXXXXXXXX"
ARG SHODAN_API_KEY="XXXXXXXXXXXXXX"

ARG LANG=en_US.UTF-8
ARG LANGUAGE=en_US

ARG GIT_REPOSITORY_AXIOM="https://github.com/pry0cc/axiom"
ARG GIT_REPOSITORY_RECONFTW="https://github.com/six2dez/reconftw"

##################################################
###> Do NOT change anything beyond this point <###
##################################################

FROM kalilinux/kali-rolling:latest AS base

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

ARG GIT_REPOSITORY_AXIOM
ARG GIT_REPOSITORY_RECONFTW

ENV COLLAB_SERVER=$COLLAB_SERVER
ENV XSS_SERVER=$XSS_SERVER
ENV SHODAN_API_KEY=$SHODAN_API_KEY

ENV LANG=$LANG
ENV LANGUAGE=$LANGUAGE
ENV LC_ALL=$LANG

ENV GIT_REPOSITORY_AXIOM=$GIT_REPOSITORY_AXIOM
ENV GIT_REPOSITORY_RECONFTW=$GIT_REPOSITORY_RECONFTW

ENV DEBIAN_FRONTEND=noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN=true

ENV GOROOT='/usr/local/go'
ENV GOPATH='/root/go'
ENV AXIOMPATH='/root/.axiom/interact'
ENV CARGOPATH='/root/.cargo/bin'
ENV PATH="${GOROOT}:${PATH}:${GOPATH}:${AXIOMPATH}:${CARGOPATH}"

COPY 01_nodoc /etc/dpkg/dpkg.cfg.d/

RUN <<eot
#!/bin/bash
set -x

###>> Backup .bashrc <<###
cp /root/.bashrc /root/original.bashrc

###>> Update Sources <<###
echo "deb http://kali.download/kali kali-rolling main contrib non-free" > /etc/apt/sources.list
echo "deb-src http://kali.download/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list

###>> System Configuration <<###
apt clean all
apt update
apt full-upgrade -f -y --allow-downgrades
apt install -y --no-install-recommends apt-utils ca-certificates curl git lsb-release nano wget vim jq htop nmon

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
mkdir -p /root/.axiom/
git clone ${GIT_REPOSITORY_AXIOM} /root/.axiom/
cd /root/.axiom/interact
./axiom-configure --unattended --shell Bash
## This avoids useless error messages later.
touch /root/.axiom/axiom.json
touch /root/.axiom/interact/includes/functions.sh

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

COPY amass_config.ini /root/.config/amass/config.ini
COPY github_tokens.txt /root/Tools/.github_tokens
COPY notify.conf /root/.config/notify/notify.conf

###>> Configure Axiom Provider <<###
RUN <<eot
###>> Regenerate SSH Keys <<###
# You REALLY do NOT want to use the default SSH keys in the base image
find /root/.ssh -type f -delete
ssh-keygen -b 2048 -t rsa -f /root/.ssh/axiom_rsa -q -N ""
cat /root/.ssh/axiom_rsa.pub > /root/.axiom/configs/authorized_keys
eot

COPY axiom-config.ini /root/.axiom/configs/config.ini
COPY axiom-custom-provider.json /root/.axiom/accounts/personal.json
RUN axiom-account personal
RUN az group delete --name axiom --yes --no-wait

# This command exits with return code 1, so leave the '|| :' or the build will fail.
COPY axiom-custom-provider.json /root/.axiom/accounts/personal.json
RUN axiom-build reconftw || :

## Issue 271
EXPOSE 85-90

WORKDIR /reconftw

SHELL [ "/bin/bash", "-c" ]
ENTRYPOINT [ "./reconftw.sh" ]
CMD [ "--help" ]
