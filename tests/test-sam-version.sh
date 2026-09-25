#!/usr/bin/env bash

# This script tests the version negotiation in the SAM handshake.

# Inputs and expected outputs
IN=()
EXP=()

IN+=("MIN=3.1 MAX=3.3")
EXP+=("OK VERSION=3.3")

IN+=("MAX=3.3")
EXP+=("OK VERSION=3.3")

IN+=("MAX=3.4")
EXP+=("OK VERSION=3.3")

IN+=("MIN=3.0")
EXP+=("OK VERSION=3.3")

IN+=("MIN=3.1")
EXP+=("OK VERSION=3.3")

IN+=("MIN=2.9")
EXP+=("OK VERSION=3.3")

IN+=("")
EXP+=("OK VERSION=3.3")

IN+=("MIN=3.3 MAX=3.1")
EXP+=("NOVERSION")

IN+=("MIN=3.5 MAX=2.7")
EXP+=("NOVERSION")

IN+=("MIN=2.7 MAX=3.5")
EXP+=("OK VERSION=3.3")

IN+=("MIN=afddab3vsfdsg1df MAX=dsaaffdb3ggfgfbgf1bssbf")
EXP+=("NOVERSION")

IN+=("MIN=31 MAX=31")
EXP+=("OK VERSION=3.1")


for i in $(seq 0 $((${#IN[@]} - 1))); do
	printf "HELLO VERSION ${IN[$i]} - "

	# Observed output
	OBS=$(printf "HELLO VERSION ${IN[$i]}\n" | nc -q 0 127.0.0.1 7656)

	if [ "$OBS" = "HELLO REPLY RESULT=${EXP[$i]}" ]; then
		printf "OK\n"
	else
		printf "received $OBS\n"
	fi
done


