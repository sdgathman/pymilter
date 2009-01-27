#!/bin/sh
appname="$1"
script="${2:-${appname}}"
datadir="/var/log/milter"
piddir="/var/run/milter"
libdir="/usr/lib/pymilter"
python="python2.4"
exec >>${datadir}/${appname}.log 2>&1
if test -s ${datadir}/${script}.py; then
  cd ${datadir} # use version in log dir if it exists for debugging
else
  cd ${libdir}
fi

${python} ${script}.py &
echo $! >${piddir}/${appname}.pid
