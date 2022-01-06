# Zeek_Rita_Docker-Compose

This is a docker-compose project to incorporate RITA and ZEEK docker images for adhoc Beacon analysis.

Step 1: 
place pcap in the /zeek_logs_pcap folder. test.pcap already exits if you want to test. you can use the command below to test the conatainer. 

docker-compose run --rm zeek -r test.pcap

Step 2: 





The basic commands for each tool are located in the commands.txt.
In theory you can coppy and paste the commands, and find the cobalt strike beacon in the test pcap.
