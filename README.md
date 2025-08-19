![](environments/static/attack-data-logo.png)

A Repository of curated datasets from various attacks to:

* Easily develop detections without having to build an environment from scratch or simulate an attack.
* Test detections, specifically [Splunks Security Content](https://github.com/splunk/security-content)
* [Replay](#replay-datasets-) into streaming pipelines for validating your detections in your production SIEM

# Installation
Notes:
* These steps are inteded to be ran on your actual Splunk host/server (not remotely)

GitHub LFS is used in this project. For Mac users git-lfs can be derived with homebrew (for another OS click [here](https://github.com/git-lfs/git-lfs/wiki/Installation)):

````
brew install git-lfs
````

Then you need to install it. I would recommend using the --skip-smudge parameter, which will avoid that all Git LFS files are downloaded during git clone. You can install it with the following command:

````
git lfs install --skip-smudge
````

Download the repository with this command:

````
git clone https://github.com/splunk/attack_data
````

Fetch all or select attack data sets

````
# This pulls all data - Warning >9Gb of data
git lfs pull

# This pulls one data set directory
git lfs pull --include=datasets/attack_techniques/T1003.001/atomic_red_team/

# Or pull just one log like this
git lfs pull --include=datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log

````


# Anatomy of a Dataset 🧬
### Datasets
example:
```
author: Patrick Bareiss
id: cc9b25e1-efc9-11eb-926b-550bf0943fbb
date: '2020-10-08'
description: 'Atomic Test Results: Successful Execution of test T1003.003-1 Create
  Volume Shadow Copy with NTDS.dit Successful Execution of test T1003.003-2 Copy NTDS.dit
  from Volume Shadow Copy Successful Execution of test T1003.003-3 Dump Active Directory
  Database with NTDSUtil Successful Execution of test T1003.003-4 Create Volume Shadow
  Copy with WMI Return value unclear for test T1003.003-5 Create Volume Shadow Copy
  with Powershell Successful Execution of test T1003.003-6 Create Symlink to Volume
  Shadow Copy '
environment: attack_range
directory: atomic_red_team
mitre_technique:
- T1003.003
datasets:
- name: crowdstrike_falcon
  path: /datasets/attack_techniques/T1003.003/atomic_red_team/crowdstrike_falcon.log
  sourcetype: crowdstrike:events:sensor
  source: crowdstrike
- name: 4688_windows-security
  path: /datasets/attack_techniques/T1003.003/atomic_red_team/4688_windows-security.log
  sourcetype: XmlWinEventLog
  source: XmlWinEventLog:Security
- name: windows-sysmon
  path: /datasets/attack_techniques/T1003.003/atomic_red_team/windows-sysmon.log
  sourcetype: XmlWinEventLog
  source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```


### Environments

Environments are a description of where the dataset was collected. At this moment there are no specific restrictions, although we do have a simple [template](https://github.com/splunk/attack_data/blob/master/environments/TEMPLATE.md) a user can start with here. The most common environment for most datasets will be the [attack_range](https://github.com/splunk/attack_data/blob/master/environments/attack_range.md) since this is the tool that used to generate attack data sets automatically.

# Replay Datasets 📼
Most datasets generated will be raw log files. There are two main simple ways to ingest it.

### Into Splunk


##### using replay.py
pre-requisite, clone, create virtual env and install python deps:

```
git clone git@github.com:splunk/attack_data.git
cd attack_data
pip install virtualenv
virtualenv venv
source venv/bin/activate
pip install -r bin/requirements.txt
```

0. Download dataset 
1. configure [`bin/replay.yml`](/bin/replay.yml) 
2. run `python bin/replay.py -c bin/replay.yml`


##### using UI

0. Download dataset
1. In Splunk enterprise , add data -> Files & Directories -> select dataset
2. Set the sourcetype as specified in the YML file
3. Explore your data

See a quick demo 📺 of this process [here](https://www.youtube.com/watch?v=41NAG0zGg40).

# Contribute Datasets 🥰

1. Generate a dataset
2. Under the corresponding MITRE Technique ID folder create a folder named after the tool the dataset comes from, for example: `atomic_red_Team`
3. Make PR with <tool_name_yaml>.yml file under the corresponding created folder, upload dataset into the same folder.

See [T1003.002](datasets/attack_techniques/T1003.003/atomic_red_team/) for a complete example.

Note the simplest way to generate a dataset to contribute is to launch your simulations in the attack_range, or manually attack the machines and when done dump the data using the [dump function](https://github.com/splunk/attack_range#dump-log-data-from-attack-range).

See a quick demo 📺 of the process to dump a dataset [here](https://www.youtube.com/watch?v=CnD0BtjCILs).

To contribute a dataset simply create a PR on this repository, for general instructions on creating a PR [see this guide](https://gist.github.com/Chaser324/ce0505fbed06b947d962).

# Automatically generated Datasets ⚙️

This project takes advantage of automation to generate datasets using the attack_range. You can see details about this service on this [sub-project folder attack_data_service](https://github.com/splunk/attack_data/tree/master/attack_data_service).

## Author
* [Patrick Bareiß](https://twitter.com/bareiss_patrick)
* [Jose Hernandez](https://twitter.com/d1vious)


## License

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
