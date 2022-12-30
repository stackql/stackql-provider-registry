#!/usr/bin/env bash

infile=$1
outfile=$2

echo "Signing $infile..."

./ed25519tool sign --privatekeyenvvar=SIGNING_PRIV_KEY $infile -o $outfile
