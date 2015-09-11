#!/bin/bash

HOST=192.168.1.3
BASEURL=/dash/
numberOfTries=10
DLOGFILE=download.log
TEMPPLOTFILE=temp.plot.file
currentDate=$(date +%H-%M-%S@%d-%m-%Y)
allPlotFile=all.files.data-$currentDate
OUTPUT=output.log

rm $OUTPUT

for file in $(cat $DLOGFILE)
do
	ab -v2 -n 500 -g $TEMPPLOTFILE http://$HOST/$BASEURL/$file >> $OUTPUT
	cat $TEMPPLOTFILE | grep -v "starttime" >> $allPlotFile
	rm $TEMPPLOTFILE
done

