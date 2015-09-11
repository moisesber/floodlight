#!/bin/bash
#BASESEC=bunny_10s
logFile=$(pwd)/download.log

echo "Log file will be $logFile"


rm $logFile
declare -a secs=("bunny_6s" "bunny_15s" "bunny_2s")

for sec in "${secs[@]}"
do
	BASESEC=$sec

	declare -a res=($BASESEC"_150kbit" $BASESEC"_500kbit" $BASESEC"_1500kbit" $BASESEC"_5000kbit")

	mkdir $BASESEC
	cd $BASESEC
	for resolution in "${res[@]}"
	do
		mkdir $resolution
		cd $resolution
		for i in $(seq 1 60)
		do
			echo "BigBuckBunny/$BASESEC/$resolution/$BASESEC$i.m4s" >> "$logFile"
			wget http://www-itec.uni-klu.ac.at/ftp/datasets/mmsys12/BigBuckBunny/$BASESEC/$resolution/$BASESEC$i.m4s
		done
		cd ..
	done
	cd ..
done

