#!/bin/bash

if [[ $# -lt 1 ]]
then
    echo "Test name required"
    exit 1
fi

NAME="${1}"
CRT="${HOME}/.config/pytutamen_client/accounts/a6cea2c2-e363-48cb-842b-dd01b3d2da99/clients/e6a49666-bdbc-47e8-8d3d-b5328aa76a65/vrg1_crt.pem"
KEY="${HOME}/.config/pytutamen_client/accounts/a6cea2c2-e363-48cb-842b-dd01b3d2da99/clients/e6a49666-bdbc-47e8-8d3d-b5328aa76a65/key.pem"
COL="58d358d0-7fdb-4970-b920-7c77c49a92b1"
SEC="b80b481b-39cd-4bda-bf36-cbff8c631234"

echo "get_ac_auth"
./benchmark_rate.py "${CRT}" "${KEY}" 10 91 10 100 get_ac_auth | tee "${HOME}/${NAME}_get_ac_auth.ssv"
./benchmark_rate.py "${CRT}" "${KEY}" 100 191 10 200 get_ac_auth | tee -a "${HOME}/${NAME}_get_ac_auth.ssv"

echo "get_ss_secret"
./benchmark_rate.py "${CRT}" "${KEY}" 10 91 10 100 get_ss_secret "${COL}" "${SEC}" | tee "${HOME}/${NAME}_get_ss_secret.ssv"
./benchmark_rate.py "${CRT}" "${KEY}" 100 191 10 200 get_ss_secret "${COL}" "${SEC}" | tee -a "${HOME}/${NAME}_get_ss_secret.ssv"
