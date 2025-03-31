#!/bin/sh
# TODO: change to 100+
NUMCERTS=5
OVPN_DATA="{{ data }}"
IMAGE="{{ image }}"

for i in $(seq 1 $NUMCERTS)
do
        docker run -v $OVPN_DATA:/etc/openvpn --rm -it $IMAGE easyrsa --batch build-client-full client-cert-$(printf "%03d" $i) nopass;
done
