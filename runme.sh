#!/bin/bash
set -e

MATCH=20

./main -i targets.csv ${MATCH} | xz -9 > log1.txt.xz &
./main -i targets.csv ${MATCH} | xz -9 > log2.txt.xz &
./main -i targets.csv ${MATCH} | xz -9 > log3.txt.xz &
./main -i targets.csv ${MATCH} | xz -9 > log4.txt.xz &
wait
