#!/bin/bash

sudo nice -n -10 java -Xmx1g -jar floodlight.jar

DATE=$(date +%H-%M-%S@%d-%m-%Y)

sudo mv delays.log experiments/delays-$DATE.log
