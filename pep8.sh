#!/bin/sh
ignore=`awk -F\\\\t '{ print $1 }' pep8.dat | tail -n +2`
a=(${ignore})
list=$(echo "${a[@]}"|tr '[ ]' '[,]')
echo python3 -m pep8 --ignore="$list" $@
