#!/bin/sh
# This is a rather inefficient way of downloading the certs;
# besides, they should be exported in the PKI dump.
# In any case, it's useful for being able to pick particular ranges
# so I'm adding it here.
OVPN_DATA=ovpn_data
CERTDIR=~/backups/certs

# TODO: change to 100
NUMCERTS=5
IMAGE=openvpn-docker

mkdir -p $CERTDIR
for i in $(seq 1 $NUMCERTS)
do
        CERT=client-cert-$(printf "%03d" $i)
        echo "fetching $CERT"
        docker run -v $OVPN_DATA:/etc/openvpn \
        --rm \
        $IMAGE \
        ovpn_getclient $CERT > $CERTDIR/$CERT.ovpn
done
