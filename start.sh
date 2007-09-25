#!/bin/sh
appname="$1"
script="${2:-${appname}}"
datadir=/var/log/milter
python="python2.4"
exec >>${datadir}/${appname}.log 2>&1
if test -s ${datadir}/${script}.py; then
  cd ${datadir} # use version in log dir if it exists for debugging
else
  cd /usr/lib/pymilter
fi

${python} ${script}.py &
echo $! >/var/run/milter/${appname}.pid
