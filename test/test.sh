#!/bin/bash

set -e

verifier_count=$1
ecclesia_root=..

generate_key="$ecclesia_root/bin/generate_key"
verifier="$ecclesia_root/bin/verifier"
directory="$ecclesia_root/bin/directory"

trap 'kill -TERM $PIDS' TERM INT

PIDS=''

mkdir -p keys
mkdir -p out

$generate_key -public keys/directory.pub.key -secret keys/directory.sec.key

KEYFILES=""

echo > verifiers.conf
for i in $(seq $verifier_count); do
    $generate_key -public keys/verifier$i.pub.key \
		  -secret keys/verifier$i.sec.key
    cat keys/verifier$i.pub.key >> verifiers.conf
    echo >> verifiers.conf
done

$directory -key keys/directory.sec.key -cycle=10s -log out/ &
PIDS="$PIDS $!"

for i in $(seq $verifier_count); do
    $verifier -key keys/verifier$i.sec.key \
	      -bind :$((8080+i)) \
	      -advertise localhost:$((8080+i))  &
    PIDS="$PIDS $!"
done

wait
