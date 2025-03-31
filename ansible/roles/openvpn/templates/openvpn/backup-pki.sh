#!/bin/sh
#
# Create a backup of the initial openvpn data volume.
# This should be kept safe, and used to re-create
# the OpenVPN pki
#
OVPN_DATA="{{ data }}"
ENDPOINT="{{ endpoint }}"
IMAGE="{{ image }}"
ALPINE=alpine:latest
BACKUP=openvpn-pki.tar.gz
CERTS=client-certs.tar.gz

# launch a container with the volume attached
docker run --rm --name=ovpn-cp -d -v $OVPN_DATA:/etc/openvpn $ALPINE
mkdir -p ~/backups

# backup the whole openvpn folder, including the pki dir
docker cp ovpn-cp:/etc/openvpn ~/backups
cd ~/backups && tar cvzf ~/backups/$BACKUP openvpn
rm -rf ~/backups/openvpn
docker stop ovpn-cp && docker rm ovpn-cp

# backup the certificates separatedly
cd ~/backups && tar cvzf ~/backups/$CERTS certs

echo "PKI Backup in $HOME/backups/$BACKUP"
echo "Certs Backup in $HOME/backups/$CERTS"
