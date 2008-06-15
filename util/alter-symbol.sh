#!/bin/sh

PATTERN="([^a-zA-Z>._!*-])$1([^a-zA-Z_!*-])"

for FILE in $(find vm sys mod -name '*.c' -o -name '*.ms')
do if egrep $PATTERN $FILE >/dev/null
   then FILES="$FILES $FILE"
   fi
done

exec vim -p $FILES
