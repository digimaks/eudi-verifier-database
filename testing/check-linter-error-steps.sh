#!/bin/env sh

if [ "$(grep level /tmp/output.txt | grep -c 'error' )" -ge 1 ]
then echo "FAILED!!!"
     cat /tmp/output.txt
     exit 1
else
   cat /tmp/output.txt
   exit 0
fi
