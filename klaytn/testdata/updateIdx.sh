#!/bin/bash

file="block_response_133998626"
postFix='.json'
fileName=$file$postFix
tmpFileName=${file}"_tmp"${postFix}
sed -n '159,10170p' $fileName > $tmpFileName


startline=0
lines=$(tail -n +$startline $tmpFileName | grep -n '"index"' | awk '{print $1}' FS=":")

for line in $lines; do
  lineContents=$(awk "NR==${line}" $tmpFileName)
  idx=$(echo $lineContents | sed -e "s/\"index\": //g")
  newidx=$(($idx+2))
  sed -i '.bak' "${line}s/\"index\": \(.*\)/\"index\": ${newidx}/g" $tmpFileName
  startline=$(($line + 1))
done