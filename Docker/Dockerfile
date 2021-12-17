# syntax=docker/dockerfile:1.3-labs

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

FROM kalilinux/kali-rolling:latest

## You can change this
ENV COLLAB_SERVER='XXXXXXXXXX'
ENV XSS_SERVER='XXXXXXXXXXX'
ENV SHODAN_API_KEY='XXXXXXXXXXXXXX'

## Do NOT change this
ENV DEBIAN_FRONTEND=noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN=true
ENV GOPATH=$HOME/go
ENV GOROOT=/usr/local/go
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH

LABEL org.label-schema.name='reconftw'
LABEL org.label-schema.description='A simple script for full recon'
LABEL org.label-schema.usage='https://github.com/six2dez/reconftw'
LABEL org.label-schema.url='https://github.com/six2dez/reconftw'
LABEL org.label-schema.docker.cmd.devel='docker run --rm -ti six2dez/reconftw'
LABEL MAINTAINER="six2dez"

RUN <<eot
#!/bin/bash
set -x
############> Update Sources <############
echo "deb http://kali.download/kali kali-rolling main contrib non-free" > /etc/apt/sources.list
echo "deb-src http://kali.download/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list
############> System Update <############
apt update
apt full-upgrade -f -y --allow-downgrades
apt install -y git wget
############> Install Golang <############
GO_BIN=$(wget -qO- https://golang.org/dl/ | grep -oP 'go([0-9\.]+)\.linux-amd64\.tar\.gz' | head -n 1)
wget https://dl.google.com/go/${GO_BIN}
tar -xzf ${GO_BIN} -C /usr/local
ln -sf /usr/local/go/bin/go /usr/bin
############> Install reconFTW <############
mkdir -p /root/Tools
cd /root/Tools
git clone https://github.com/six2dez/reconftw.git
cd reconftw
./install.sh
############> Clean up <############
rm -f "/${GO_BIN}"
go clean -cache -modcache
apt autoremove -y
apt clean all
find /var/cache -type f -delete
find /var/lib/apt/lists -type f -delete
find /var/log -type f -delete
eot

COPY amass_config.ini /root/.config/amass/config.ini
COPY github_tokens.txt /root/Tools/.github_tokens
COPY notify.conf /root/.config/notify/notify.conf
COPY subfinder_config.yaml /root/.config/subfinder/config.yaml

WORKDIR /root/Tools/reconftw
ENTRYPOINT ["bash", "reconftw.sh"]
CMD [ "--help" ]