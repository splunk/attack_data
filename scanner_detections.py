import yaml
import glob

import os.path
import sys
import os
import urllib.request
import time

import queue


    
URL_PREFIX = "https://media.githubusercontent.com/media/splunk/attack_data/master/"

#DETECTIONS_PATH = "/Users/emcginnis/Documents/GitHub/DetectionDevelopment/security_content/detections/{endpoint,web,network,cloud}/*.yml"
DETECTIONS_PATHS = [f"/Users/emcginnis/Documents/GitHub/DetectionDevelopment/security_content/detections/{folder}/*.yml" for folder in ["endpoint","web","cloud","network"]]
print(DETECTIONS_PATHS)
#all_files = glob.glob("datasets/**/*.yml", recursive=True)
all_files = []

for current_path in DETECTIONS_PATHS:
    all_files += glob.glob(current_path, recursive=True)

print(f"The number of yml files we will check is [{len(all_files)}]")
failure = False
url_failures = []
urls = dict()
total_refs = 0
saved_refs = 0
attempted_refs = 0

for yaml_file in all_files:
    print(f"{all_files.index(yaml_file)} of {len(all_files)}")
    #Ignore the TEMPLATE file
    if os.path.basename(yaml_file) == "TEMPLATE.yml":
        continue

    try:
        #print(f"Loading {yaml_file}...",end='')
        with open(yaml_file, "r") as yf:
            yaml_data = yaml.safe_load(yf)
        
        
        if 'references' in yaml_data and len(sys.argv) > 1 and sys.argv[1] == "check_urls" :
            for ref in yaml_data['references']:
                total_refs += 1
                if ref in urls:
                    print(f"(SAVED){ref}: {urls[ref]}")
                    saved_refs += 1
                else:
                    attempted_refs += 1
                    try:
                        print(f"{ref}: ",end='')
                        sys.stdout.flush()
                        headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36"}
                        #From an up-to-date version of Chrome.... there don't appear to be any packages that provide more robust headers, just user-agent. Which is not enough
                        headers =  {"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                                    "accept-language": "en-US,en;q=0.9",
                                    "cache-control": "no-cache",
                                    "pragma": "no-cache",
                                    "sec-ch-ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"99\", \"Google Chrome\";v=\"99\"",
                                    "sec-ch-ua-mobile": "?0",
                                    "sec-ch-ua-platform": "\"macOS\"",
                                    "sec-fetch-dest": "document",
                                    "sec-fetch-mode": "navigate",
                                    "sec-fetch-site": "none",
                                    "sec-fetch-user": "?1",
                                    "upgrade-insecure-requests": "1",
                                    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36"
                                }
                        req = urllib.request.Request(ref)
                        req.headers = headers
                        code = urllib.request.urlopen(req, timeout=20).getcode()
                        code = 200

                        #time.sleep(1)
                        print(f"{code}")
                        urls[ref] = code
                    except Exception as e:
                        print(f"Error trying to open {ref}: {str(e)}")
                        urls[ref] = f"{ref} in {yaml_file}: {str(e)}"
                    
            
        
    except Exception as e:
        print(f"Error: {str(e)}")
        failure = True

print(f"Total Refs {total_refs}")
print(f"Attempted Refs {attempted_refs}")
print(f"Saved Refs {saved_refs}")
error_refs = [entry for entry in urls if urls[entry] != 200]
print(f"Error Refs {len(error_refs)}")

print("URL Errors:")
for entry in error_refs:
    if urls[entry] != 200:
        print(f"{urls[entry]}")

http_refs = [entry for entry in urls if not entry.startswith("https")]
print(f"HTTP Only Refs = {len(http_refs)}")
for entry in http_refs:
        print(f"{entry}")




if failure:
    sys.exit(1)
else:
    sys.exit(0)        
