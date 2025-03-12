#!/bin/bash
CLUSTER_ID="{{ cluster_id }}"

# List all HSM tokens
echo "Listing all HSM tokens in the cluster..."
aws cloudhsmv2 describe-clusters --filters clusterIds=$CLUSTER_ID --query "Clusters[0].Hsms[*].HsmId"

# Function to delete an HSM token and wait for its deletion
delete_hsm_token() {
    HSM_ID=$1
    aws cloudhsmv2 delete-hsm --cluster-id $CLUSTER_ID --hsm-id $HSM_ID
    echo "Deleting HSM Token with ID: $HSM_ID..."

}

wait_for_them_to_die() {

    while true; do
        STATE=$(aws cloudhsmv2 describe-clusters --filters clusterIds=$CLUSTER_ID --query "Clusters[0].Hsms[*] | length(@)")
        if [ "$STATE" -eq 0 ]; then
            echo "All HSM tokens are dead. RIP."
            break
        fi
        echo "Waiting for HSM tokens to die."
        sleep 10
    done

}

# Delete all HSM tokens
HSM_IDS=$(aws cloudhsmv2 describe-clusters --filters clusterIds=$CLUSTER_ID --query "Clusters[0].Hsms[*].HsmId" --output text)
for HSM_ID in $HSM_IDS; do
    delete_hsm_token $HSM_ID
done

wait_for_them_to_die

echo "All HSM tokens have been deleted."
