import yaml
import glob

import os.path
import sys
import os
import urllib.request
import time


URL_PREFIX = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
all_files = glob.glob("datasets/**/*.yml", recursive=True)
print(f"The number of yml files we will check is [{len(all_files)}]")
failure = False
url_failures = []
urls = dict()
total_refs = 0
saved_refs = 0
attempted_refs = 0

for yaml_file in all_files:
    #Ignore the TEMPLATE file
    if os.path.basename(yaml_file) == "TEMPLATE.yml":
        continue

    try:
        #print(f"Loading {yaml_file}...",end='')
        with open(yaml_file, "r") as yf:
            yaml_data = yaml.safe_load(yf)
        
        if len(sys.argv) > 1 and sys.argv[1] == "update_yamls":
            try:
                directory = os.path.dirname(yaml_file)
                all_files = glob.glob(os.path.join(directory, "*.*"))
                new_files = [os.path.join(URL_PREFIX, os.path.relpath(f)) for f in all_files if len(os.path.splitext(f)) > 1 and os.path.splitext(f)[1]  != ".yml"]

                diff_set = set(new_files).symmetric_difference(set(yaml_data['dataset'])) 
                if len(diff_set) > 0:
                    print(f"Error: difference between datasets in yml and datasets in folder for {yaml_file}")
                    #print(set(new_files))
                    #print(set(yaml_data['dataset']))
                    for dataset in diff_set:
                        if len(sys.argv) > 2 and sys.argv[2] == "rewrite":
                            yaml_data['dataset'] = new_files
                            with open(yaml_file) as updated_yaml_file:
                                yaml.safe_dump(yaml_data, updated_yaml_file)
                        if dataset in new_files:
                            print(f"\t{dataset} in DIRECTORY[{directory}], but not in FILE[{yaml_file}]")
                        elif dataset in yaml_data['dataset']:
                            print(f"\t{dataset} in FILE[{yaml_file}], but not in DIRECTORY[{directory}]")
                        else:
                            raise(Exception("\tError printing out difference!"))
                    print("\n")
            except Exception as e:
                raise(Exception(f"some error [{e}]"))
        

        elif False:
            pass
        elif 'dataset' not in yaml_data:
            print(f"'dataset' not found in {yaml_file}")
        else:
            for entry in yaml_data['dataset']:
                try:
                    empty, dirpath = entry.split(URL_PREFIX)
                except:
                    raise(Exception(f"Bad dataset link in file {yaml_file}: {entry}"))
                if not os.path.exists(dirpath):
                    print(f"Error for {yaml_file}, {dirpath} does not exist!")
                    
        
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


                        #time.sleep(1)
                        print(f"{code}")
                        urls[ref] = code
                    except Exception as e:
                        print(f"Error trying to open {ref}: {str(e)}")
                        urls[ref] = str(e)
                    
            
        
    except Exception as e:
        print(f"Error: {str(e)}")
        failure = True

print(f"Total Refs {total_refs}")
print(f"Attempted Refs {attempted_refs}")
print(f"Saved Refs {saved_refs}")
print("URL Errors:")
for entry in urls:
    if urls[entry] != 200:
        print(f"{entry}: {urls[entry]}")

if failure:
    sys.exit(1)
else:
    sys.exit(0)        
