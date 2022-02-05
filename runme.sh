#!/bin/bash
set -e

./main ${@} | xz -9 > log1.txt.xz &
./main ${@} | xz -9 > log2.txt.xz &
./main ${@} | xz -9 > log3.txt.xz &
./main ${@} | xz -9 > log4.txt.xz &
wait
