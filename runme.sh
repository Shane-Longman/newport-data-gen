#!/bin/bash
set -e

# Call executable passed as first argument, with remaining
# arguments passed to it

./${1} ${@: 2} | xz -9 > log1.txt.xz &
./${1} ${@: 2} | xz -9 > log2.txt.xz &
./${1} ${@: 2} | xz -9 > log3.txt.xz &
./${1} ${@: 2} | xz -9 > log4.txt.xz &
wait
