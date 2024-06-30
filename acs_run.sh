#!/bin/bash

# Usage: Run `run-on-ec2_create.py`, `run-on-ec2_setup.py`
# Then run `bash acs_run.sh`
# Use collect.py to collect results.

timestamp=$(date +"%s")

timestamp=$((timestamp+15))

session_number=0

while IFS= read -r line
do
    pem_file=$(echo "$line" | awk '{print $1}')
    ip_address=$(echo "$line" | awk '{print $2}')


    tmux new-session -d -s s$session_number 
    tmux send-key -t s$session_number "ssh -i $pem_file -o StrictHostKeyChecking=no -t ubuntu@$ip_address 'rm -f /home/ubuntu/benchmark-logs/* && sudo docker run -p 7001:7001 -v /home/ubuntu/config:/usr/src/adkg/config/ -v /home/ubuntu/benchmark-logs:/usr/src/adkg/benchmark-logs/ [YOUR DOCKER IMAGE PATH] python3 -m scripts.vaba_run -d -f config/config-$session_number.json -time $timestamp'" C-m

    session_number=$(expr $session_number + 1)
done < config0



