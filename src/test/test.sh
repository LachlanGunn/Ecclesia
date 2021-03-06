#!/bin/bash

verifier_count=$1
if [ -z $verifier_count ]; then
        verifier_count=5
fi

src_path="$(realpath $(dirname $(realpath $0))/..)"
work_path="$(mktemp -d)"

generate_key="$src_path/utils/generate_key"
verifier="$src_path/verifier/verifier"
directory="$src_path/directory/directory"
read_directory="$src_path/utils/read_directory"
tls_test_server="$src_path/test/tls_test_server"
requestor="$src_path/requestor/requestor"
validate="$src_path/validator/validate"

export GIN_MODE=release

trap 'kill -TERM $PIDS $PID_DIRECTORY $PID_TEST_SERVER; rm -rf $work_path' TERM INT

PIDS=''

mkdir -p "$work_path/keys"
mkdir -p "$work_path/out"

$generate_key -public "$work_path/keys/directory.pub.key" -secret "$work_path/keys/directory.sec.key"

echo > verifiers.conf
for i in $(seq $verifier_count); do
    $generate_key -public "$work_path/keys/verifier$i.pub.key" \
		  -secret "$work_path/keys/verifier$i.sec.key"
    cat "$work_path/keys/verifier$i.pub.key" >> "$work_path/verifiers.conf"
    echo >> "$work_path/verifiers.conf"
done

$directory -bind :7998 \
           -key "$work_path/keys/directory.sec.key" \
	   -cycle=3s \
	   -log "$work_path/out/" \
	   -verifiers "$work_path/verifiers.conf" \
	   -quiet &
PID_DIRECTORY="$!"
sleep 1

for i in $(seq $verifier_count); do
    $verifier -directory localhost:7998 \
	      -key "$work_path/keys/verifier$i.sec.key" \
	      -bind :$((8080+i)) \
	      -advertise localhost:$((8080+i)) \
	      -quiet -novalidate &
    PIDS="$PIDS $!"
done

# Now that we have started the system, we need to wait for a
# directory to be emitted with the verifiers.
>&2 echo -n 'Waiting for directory publication...'
verifiers_included=0
time_waiting=0
while [ $verifiers_included -lt $verifier_count ]; do
	directory_file=$(find "$work_path/out/" | tail -n 1)
	if [ -f "$directory_file" ]; then
		verifiers_included=$($read_directory $directory_file \
				 | grep '^Found [0-9]* verifiers.$' \
				 | awk '{print $2}')
	fi
	if [ $time_waiting -gt 90 ]; then
		>&2 echo 'timeout.'
		kill -TERM $PIDS $PID_DIRECTORY
		exit 1
	fi
	sleep 5
	time_waiting=$(expr $time_waiting + 5)
	>&2 echo -n "$time_waiting..."
done
>&2 echo 'done.'

>&2 echo -n '---[1/3]--- Producing certificate...'

$tls_test_server &
PID_TEST_SERVER=$!

sleep 1

verification_count=$(expr $verifier_count / 2)
$requestor -verifiers $verification_count $directory_file localhost:7999 \
	>"$work_path/certificate.cert"
if [ $? -ne 0 ]; then
	>&2 echo 'FAIL.'
	kill -TERM $PIDS $PID_DIRECTORY $PID_TEST_SERVER
	exit 1
fi
>&2 echo 'PASS.'

>&2 echo -n '---[2/3]--- Checking valid certificate...'
$validate -verifiers $verification_count -noca \
	$directory_file "$work_path/certificate.cert" localhost:7999 2>/dev/null

if [ $? -ne 0 ]; then
	>&2 echo 'FAIL.'
	kill -TERM $PIDS $PID_DIRECTORY $PID_TEST_SERVER
	exit 1
fi

>&2 echo 'PASS.'

>&2 echo -n '---[3/3]--- Checking MITM behaviour...'
kill -TERM $PID_TEST_SERVER
$tls_test_server &
PID_TEST_SERVER=$!

sleep 1

$validate -verifiers $verification_count -noca \
	$directory_file "$work_path/certificate.cert" localhost:7999 2>/dev/null

if [ $? -ne 1 ]; then
	>&2 echo 'FAIL.'
	kill -TERM $PIDS $PID_DIRECTORY $PID_TEST_SERVER
	exit 1
fi
echo 'PASS.'

kill -TERM $PIDS $PID_DIRECTORY $PID_TEST_SERVER
rm -r "$work_path"
