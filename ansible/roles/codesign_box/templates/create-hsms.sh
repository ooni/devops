#!/bin/bash

CLUSTER_ID="{{ cluster_id }}"

create_hsm_token() {
    if [ -z $1 ]; then
       echo "AVAILABILITY ZONE PARAMETER UNSET!"
       exit 1
    fi
    AVAILABILITY_ZONE=$1
    aws cloudhsmv2 create-hsm --cluster-id $CLUSTER_ID --availability-zone $AVAILABILITY_ZONE
    echo "Creating HSM Token in $AVAILABILITY_ZONE..."
    sleep 5

}


wait_for_hsm_tokens() {

    while true; do
        STATE=$(aws cloudhsmv2 describe-clusters --filters clusterIds=$CLUSTER_ID --query "Clusters[0].Hsms[?State=='ACTIVE'] | length(@)")
        if [ "$STATE" -ge 2 ]; then
            echo "HSM Tokens created and active."
            break
        fi
        echo "Waiting for HSM Token $TOKEN_NAME to become active..."
        sleep 10
    done

}

CURRENT_TOKEN_COUNT=$(aws cloudhsmv2 describe-clusters --filters clusterIds=$CLUSTER_ID --query "Clusters[0].Hsms[?State=='ACTIVE'] | length(@)")
if [ "$CURRENT_TOKEN_COUNT" -ge 2 ]; then
    echo "Enough HSMs already exist, skipping creation"
else
    create_hsm_token eu-central-1a
    create_hsm_token eu-central-1b
    wait_for_hsm_tokens
fi

echo "Extracting IP addresses of created HSM tokens..."
IP_ADDRESSES=$(aws cloudhsmv2 describe-clusters --filters clusterIds=$CLUSTER_ID --query "Clusters[0].Hsms[*].EniIp" --output text)
echo "IP Addresses of created HSM tokens: $IP_ADDRESSES"

IP_ADDRESS_1=$(echo $IP_ADDRESSES | cut -d ' ' -f1)
IP_ADDRESS_2=$(echo $IP_ADDRESSES | cut -d ' ' -f2)

echo "[+] writing cloudhsm-cli.cfg"
cat <<EOF > /tmp/cloudhsm-cli.cfg
{
    "clusters" : [{
        "type": "hsm1",
        "cluster":{
            "hsm_ca_file": "/opt/cloudhsm/etc/customerCA.crt",
            "servers":[
                {
                    "hostname": "$IP_ADDRESS_1",
                    "port": 2223,
                    "enable": true
                },
                {
                    "hostname": "$IP_ADDRESS_2",
                    "port": 2223,
                    "enable": true
                }
            ]
        }
    }],
    "logging": {
        "log_type": "file",
        "log_file": "/opt/cloudhsm/run/cloudhsm-cli.log",
        "log_level": "info",
        "log_interval": "daily"
    }
}
EOF

sudo mv /tmp/cloudhsm-cli.cfg /opt/cloudhsm/etc/cloudhsm-cli.cfg
sudo chown root:root /opt/cloudhsm/etc/cloudhsm-cli.cfg


echo "[+] writing cloudhsm-pkcs11.cfg"
cat <<EOF > /tmp/cloudhsm-pkcs11.cfg
{
    "clusters" : [{
        "type": "hsm1",
        "cluster":{
            "hsm_ca_file": "/opt/cloudhsm/etc/customerCA.crt",
            "servers":[
                {
                    "hostname": "$IP_ADDRESS_1",
                    "port": 2223,
                    "enable": true
                },
                {
                    "hostname": "$IP_ADDRESS_2",
                    "port": 2223,
                    "enable": true
                }
            ]
        }
    }],
    "logging": {
        "log_type": "file",
        "log_file": "/opt/cloudhsm/run/cloudhsm-pkcs11.log",
        "log_level": "info",
        "log_interval": "daily"
    }
}
EOF
sudo mv /tmp/cloudhsm-pkcs11.cfg /opt/cloudhsm/etc/cloudhsm-pkcs11.cfg
sudo chown root:root /opt/cloudhsm/etc/cloudhsm-pkcs11.cfg