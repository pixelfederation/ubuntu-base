################################################################################
# ubuntu-base:1.1.0
# Date: 12/24/2015
# 
# Description:
# Base Ubuntu build with logstash forwarder, supervisor, and various
# helper scripts.
################################################################################

FROM ubuntu:14.04
MAINTAINER Bob Killen / killen.bob@gmail.com / @mrbobbytables


ENV DEBIAN_FRONTEND=noninteractive

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D88E42B4                                                                \
 && echo "deb http://packages.elastic.co/logstashforwarder/debian stable main" >> /etc/apt/sources.list.d/logstash-forwarder.list    \
 && apt-get -y update                                   \
 && apt-get -y install                                  \
     logstash-forwarder                                 \
     supervisor                                         \
 && apt-get clean                                       \
 && rm -rf /etc/logrotate.d/*                           \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY ./skel /

RUN chmod 640 /etc/logrotate.conf                       \
 && chmod 640 /etc/logrotate.d/*                        \
 && chmod +x /opt/scripts/container_functions.lib.sh    \
 && chmod +x /opt/scripts/logrotate.sh                  \
 && chmod +x /opt/scripts/redpill.sh                    \
 && chown -R logstash-forwarder:logstash-forwarder /opt/logstash-forwarder

