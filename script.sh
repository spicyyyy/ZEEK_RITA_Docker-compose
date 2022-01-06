#! /bin/Bash
echo "
##################################################################
#                                                                #
#                                                                #
#                   ZEEK & RITA docker-compose script         	 # 
#                                                                #
#                                                                #
##################################################################"

echo "\nThis is a simple script to automate PCAP > ZEEK > RITA > BEACONS "

echo "\nYou if the pcap is not listed below it needs to be added to the ./zeek_log_pcap folder."
ls ./zeek_logs_pcap | grep .pcap
echo "\nIf you see you pcap file. type it in and press enter. "
read pcapname
echo "\n\nInsert a name of your choosing for the output of RITA beacon results, then press enter. "
read ritadb

#zeek command for pcap to zeek
export pcapnamew=$pcapname
docker-compose run -e pcapnamew --rm zeek -r $pcapnamew

wait

#rita command to import logs
export ritadbw=$ritadb
docker-compose run -e ritadbw --rm rita import /logs $ritadbw

wait
#rita show-beacons and write to file
docker-compose run -e retadw --rm rita show-beacons $ritadbw > $ritadbw.csv

echo "/n/nYour results are in the $retadw file."