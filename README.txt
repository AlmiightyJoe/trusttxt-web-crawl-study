This project is used to identify and analyze the presence of trust.txt files across media-related domains.

The crawler checks two standard locations on each domain:
 - /.well-known/trust.txt
 - /trust.txt
 
 The response is retrieved, classified, and stored as one of the following:
- Valid trust.txt files
- False positive responses (e.g. HTML pages, redirects)
- Failed attempts (e.g. timeouts, access denied)

-------------------------------------------------------------------

Setup:

1. Make sure Python 3 is installed.

2. Install required dependencies:
	pip install -r requirements.txt

-------------------------------------------------------------------

Seed generation (building input datasets)
Seed files can be generated using the scripts located in /scripts/.

Media organization seeds (Wikipedia based):
EU:
python3 scripts/build_media_orgs_eu.py
US:
python3 scripts/build_media_orgs_us.py

Output:
- seeds/seeds_media_orgs_eu.txt
- seeds/seeds_media_orgs_us.txt

News site seeds (W3Newspapers-based):
EU:
python3 scripts/build_news_seeds_EU.py
US:
python3 scripts/build_news_seeds_US.py

Output:
- seeds/news_eu.txt
- seeds/news_us.txt

Note:
All seed files contain one domain per line and are used as input for the crawler.

-------------------------------------------------------------------

How to run the crawler (Option 1/Option 2):

Option 1 - Run a single dataset manually:


1. Select the dataset to crawl by editing the configuration file:
	config/config_v2.json
	
2. Update the following fields with the corresponding:
	- "output_dir" -> input dataset
	- "seeds_file" -> where results are stored
	- "visited_file" -> tracking file for processed domains (optional)

3. Run the crawler:
	python3 crawler_v2.py --config config/config_v2.json

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	
Option 2 - Run multiple datasets using run.py

1. Update the datasets in:
	- config/eu.json
	- config/us.json
	
2. Update the following fields in each file:
	- "output_dir" -> input dataset
	- "seeds_file" -> where results are stored
	- "visited_file" -> tracking file for processed domains (optional)
	
5. Run:
	python3 run.py

This executes both configurations sequentially.

-------------------------------------------------------------------

Input datasets:

Supported seed files include:
- news_eu.txt
- news_us.txt
- seeds_media_orgs_eu.txt
- seeds_media_orgs_us.txt

-------------------------------------------------------------------

Output:

Results are written to the configured output directories:
- found/ 	-> valid trust.txt files
- false_positives/ -> non-valid responses
- not_found/ 	-> domains without valid implementations

CSV files:
- found/found_v2.csv
- not_found/not_found_v2.csv

-------------------------------------------------------------------

Notes:

- The crawler uses a delay between requests to avoid overloading servers.
- Only publicly accessible data is collected.
- Responses are classified based on content, not just HTTP status codes.
