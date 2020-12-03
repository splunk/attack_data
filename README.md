# Attack Data Repository 🧱
A Repository of curated datasets from various attacks to:

* Easily develop detections without having to build an environment from scratch or simulate an attack.
* Test detections, specifically [Splunks Security Content](https://github.com/splunk/security-content)
* Replay/inject into streaming pipelines for validating your detections in your production SIEM

# Installation
GitHub LFS is used in this project. Here is a [tutorial](https://git-lfs.github.com/) how to install and use it.

# Anatomy of a Dataset 🧬
### Datasets
Datasets are defined by a common yml structure. The structure has the following fields:

|field| description|
|---|---|
|name  | name of author  |
| date  | last modified date  |
| dataset  | array of urls where the hosted version of the dataset is located  |
| description | describes the dataset as detailed as possible |
| environment |  markdown filename of the environment description see below |
| technique | array of MITRE ATT&CK techniques associated with dataset |
| references | array of urls that reference the dataset |
| sourcetypes | array of sourcetypes that are contained in the dataset |


For example

```
author: Patrick Bareiss
date: '2020-10-08'
description: 'Atomic Test Results: Successful Execution of test T1003.001-1 Windows
  Credential Editor Successful Execution of test T1003.001-2 Dump LSASS.exe Memory
  using ProcDump Return value unclear for test T1003.001-3 Dump LSASS.exe Memory using
  comsvcs.dll Successful Execution of test T1003.001-4 Dump LSASS.exe Memory using
  direct system calls and API unhooking Return value unclear for test T1003.001-6
  Offline Credential Theft With Mimikatz Return value unclear for test T1003.001-7
  LSASS read with pypykatz '
environment: attack_range
technique:
- T1003.001
dataset:
- https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-powershell.log
- https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-security.log
- https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log
- https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-system.log
references:
- https://attack.mitre.org/techniques/T1003/001/
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md
- https://github.com/splunk/security-content/blob/develop/tests/T1003_001.yml
sourcetypes:
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
- WinEventLog:Microsoft-Windows-PowerShell/Operational
- WinEventLog:System
- WinEventLog:Security
```


### Environments

Environments are a description of where the dataset was collected. At this moment there are no specific restrictions, although we do have a simple [template](https://github.com/splunk/attack_data/blob/master/environments/TEMPLATE.md) a user can start with here. The most common environment for most datasets will be the [attack_range](https://github.com/splunk/attack_data/blob/master/environments/attack_range.md) since this is the tool that used to generate attack data sets automatically.

# Ingest Datasets 🍽
Most datasets generated will be raw log files. There are two main simple ways to ingest it.

### Into Splunk

0. Download dataset
1. In splunk enterprise , add data -> Files & Directories -> select dataset
2. Set the sourcetype as specified in the yml file
3. Explore your data

See a quick demo 📺 of this process [here](https://www.youtube.com/watch?v=41NAG0zGg40).

### Into DSP

To send datasets into DSP the simplest way is to use the [scloud](https://docs.splunk.com/Documentation/DSP/1.1.0/Admin/AuthenticatewithSCloud) command-line-tool as a requirement.

1. Download the dataset
2. Ingest the dataset into DSP via scloud command `cat attack_data.json | scloud ingest post-events --format json`
3. Build a pipeline that reads from firehose and you should see the events.

# Contribute Datasets 🥰

1. Generate a dataset
2. Upload dataset into same folder
3. Make PR with dataset <name>.yml file under the corresponding MITRE ATT&CK technique folder.

Note the simplest way to generate a dataset to contribute is to launch your simulations in the attack_range, or manually attack the machines and when done dump the data using the [dump function](https://github.com/splunk/attack_range#dump-log-data-from-attack-range).

See a quick demo 📺 of the process to dump a dataset [here](https://www.youtube.com/watch?v=CnD0BtjCILs).

To contribute a dataset simply create a PR on this repository, for general instructions on creating a PR [see this guide](https://gist.github.com/Chaser324/ce0505fbed06b947d962).

# Automatically generated Datasets ⚙️

This project takes advantage of automation to generate datasets using the attack_range. You can see details about this service on this [sub-project folder attack_data_service](https://github.com/splunk/attack_data/tree/master/attack_data_service).

## Author
* [Patrick Bareiß](https://twitter.com/bareiss_patrick)
* [Jose Hernandez](https://twitter.com/d1vious)


## License

Copyright 2020 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
