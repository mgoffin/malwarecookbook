#!/bin/bash

TSOCKS=`which usewithtor`
WGET=`which wget`

if [ $# -eq 0 ]; then

  echo "Please enter a URL to request";
  exit;

fi

$TSOCKS $WGET $1 -U "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; GTB6; .NET CLR 1.1.4322)"

