# Zeek_Rita_Docker-Compose

This is a docker-compose project to incorporate RITA and ZEEK docker images for adhoc beacon analysis.



**Step 1:** 

Place the pcap you want to analyze in /zeek_logs_pcap. 
test.pcap already exits if you want to test for an example.

If you already have ZEEK logs you want rita to analyze, place the logs in /zeek_logs_pcap and skip to step 3. 


**Step 2:**

Run the below command to create ZEEK logs to be analyzed by RITA. 
If you already have zeek logs, skip this step, but place the logs in /zeek_logs_pcap. 

docker-compose run --rm zeek -r test.pcap


**Step 3:**

Run RITA and place in specified database on MONGO.

docker-compose run --rm rita import /logs db1


**Step 4:** 

Write the RITA beacons to a .csv file.

docker-compose run --rm rita show-beacons db1 > ./beacon_results/db1_beacons.csv
