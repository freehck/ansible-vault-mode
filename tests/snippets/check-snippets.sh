#!/bin/bash

## Examples:
# ./check-snippets.sh decrypted
# ./check-snippets.sh encrypted_11

export ANSIBLE_LOAD_CALLBACK_PLUGINS=true
export ANSIBLE_STDOUT_CALLBACK=json
ansible localhost -e @snippets.yaml -m debug -a "msg={{ $1 }}" | jq -r '.plays[0].tasks[0].hosts.localhost.msg'
