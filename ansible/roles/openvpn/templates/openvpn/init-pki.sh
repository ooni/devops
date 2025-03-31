#!/bin/sh
OVPN_DATA="{{ data }}"
ENDPOINT="{{ endpoint }}"
IMAGE="{{ image }}"
ALPINE=alpine:latest

#
# This script will fail if the volume is already initialized!
#
# generate configuration boilerplate. udp:// does not matter because we'll override the config file
docker run -v $OVPN_DATA:/etc/openvpn --rm $IMAGE ovpn_genconfig -u udp://$ENDPOINT
# generate the password-less PKI
docker run -v $OVPN_DATA:/etc/openvpn --rm -i $IMAGE ovpn_initpki nopass
# remove the ccd folder
docker run --rm -d -v $OVPN_DATA:/etc/openvpn $ALPINE rm -rf /etc/openvpn/ccd
