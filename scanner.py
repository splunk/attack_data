import yaml
import glob
from os.path import exists
import sys

URL_PREFIX = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
all_files = glob.glob("**/*.yml", recursive=True)
print(f"The number of yml files we will check is [{len(all_files)}]")
failure = False
for yaml_file in all_files:
    try:
        #print(f"Loading {yaml_file}...",end='')
        with open(yaml_file, "r") as yf:
            yaml_data = yaml.safe_load(yf)
        
        if 'dataset' not in yaml_data:
            print(f"'dataset' not found in {yaml_file}")
        else:
            for entry in yaml_data['dataset']:
                try:
                    empty, dirpath = entry.split(URL_PREFIX)
                except:
                    raise(Exception(f"Bad dataset link in file {yaml_file}: {entry}"))
                if not exists(dirpath):
                    print(f"Error for {yaml_file}, {dirpath} does not exist!")
                    
                else:
                    pass
        
    except Exception as e:
        print(f"Error: {str(e)}")
        failure = True

if failure:
    sys.exit(1)
else:
    sys.exit(0)        
