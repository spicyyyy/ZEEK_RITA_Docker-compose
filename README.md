# ZEEK_RITA_docker-compose

This is a docker-compose project to incorporate RITA and ZEEK docker images for adhoc beacon analysis.

Original docker-compose.yaml came frome active countersmeasures RITA repository. 
blacktop/zeek was added to the docker-compose file for an easy spin up of all containers.


**Easy Mode:** Run the script! It automates the show beacons portion of rita.
* the script is not fancy, pay attention to the wording. No tab completions!

Place the pcap you want to analyze in /zeek_logs_pcap. 
test.pcap already exits if you want to test for an example.

``` sh script.sh ```


***STEPS WITHOUT THE SCRIPT***

**Step 1:** 

Place the pcap you want to analyze in /zeek_logs_pcap. 
test.pcap already exits if you want to test for an example.

If you already have ZEEK logs you want RITA to analyze, place the logs in /zeek_logs_pcap and skip to step 3. 


**Step 2:**

Run the below command to create ZEEK logs to be analyzed by RITA. 
If you already have zeek logs, skip this step, but place the logs in /zeek_logs_pcap. 

```docker-compose run --rm zeek -r test.pcap```


**Step 3:**

Run RITA and place in specified database on MONGO.

```docker-compose run --rm rita import /logs db1```


**Step 4:** 

Write the RITA beacons to a .csv file.

```docker-compose run --rm rita show-beacons db1 > ./beacon_results/db1_beacons.csv```
