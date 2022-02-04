#!/usr/bin/env bash

set -eux

OIDC_TOKEN="NOP"
PUBLIC_KEY=$(cat wg-keys/publickey-github)
PRIVATE_KEY=$(cat wg-keys/privatekey-github)
#BASTION_API_ENDPOINT=http://localhost:8080
BASTION_API_ENDPOINT=http://104.155.25.145:8080

export OIDC_TOKEN
export PUBLIC_KEY
export PRIVATE_KEY
export BASTION_API_ENDPOINT

./tinyclient
