#!/bin/bash
set -e

if [ -f title-art.txt ]; then
    cat title-art.txt
fi

if [ -z ${DESTINATION_ACR+x} ]; then
	echo "DESTINATION_ACR parameter is not set. Exiting..."
	exit 1;
fi

if [ -z ${TARBALL_IMAGE_FILE_SAS+x} ]; then
	echo "TARBALL_IMAGE_FILE_SAS parameter is not set. Exiting..."
	exit 1;
fi

if [ -z ${IMAGE_NAME+x} ]; then
	echo "IMAGE_NAME parameter is not set. Exiting..."
	exit 1;
fi

if [ -z ${IMAGE_TAG_NAME+x} ]; then
	echo "IMAGE_TAG_NAME parameter is not set. Exiting..."
	exit 1;
fi

apt update
apt-get install -y unzip wget gzip

# Login cli using managed identity
az login --identity

echo "Downloading docker tarball image from ${DESTINATION_ACR}"
wget -O telegraf-image.tar "${TARBALL_IMAGE_FILE_SAS}"

echo "Getting credentials for registry ${DESTINATION_ACR}"
QUERY_RESPONSE=$(az acr login --name "${DESTINATION_ACR}" -t)
ACCESS_TOKEN=$(echo "$QUERY_RESPONSE" | jq -r '.accessToken')
DESTINATION_ACR=$(echo "$QUERY_RESPONSE" | jq -r '.loginServer')
crane auth login "${DESTINATION_ACR}" -u "00000000-0000-0000-0000-000000000000" -p "${ACCESS_TOKEN}"

TELEGRAF_IMAGE_FULL_NAME="${DESTINATION_ACR}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}"

if [[ $TELEGRAF_IMAGE_FULL_NAME == *"tar.gz"* ]]; then
	gunzip $TELEGRAF_IMAGE_FULL_NAME
fi

echo "Pushing image ${TELEGRAF_IMAGE_FULL_NAME}"
crane push "telegraf-image.tar" "${TELEGRAF_IMAGE_FULL_NAME}"