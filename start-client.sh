#!/usr/bin/env bash

set -eux

OIDC_TOKEN="NOP"
PUBLIC_KEY=$(cat wg-keys/publickey-github)
BASTION_API_ENDPOINT=http://localhost:8080

export OIDC_TOKEN
export PUBLIC_KEY
export BASTION_API_ENDPOINT

./tinyclient
