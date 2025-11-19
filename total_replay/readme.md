# TOTAL-REPLAY

![TOTAL-REPLAY](assets/banner.png)

## Description

This lightweight tool helps you make the most of Splunk’s [Security Content](https://github.com/splunk/security_content) metadata, such as detection names, analytic stories, and more, by replaying relevant test event logs or attack data from either the [Splunk Attack Data](https://github.com/splunk/attack_data) or [Splunk Attack Range](https://github.com/splunk/attack_range) projects.

## Installation

### MAC/LINUX
#### TOTAL-REPLAY IN SPLUNK ATTACK-DATA REPO
1. Clone the Splunk Security Content github repo. We recommend to follow this steps [Security Content Getting Started](https://github.com/splunk/security_content).

2. Install Poetry (if not already installed)
```
curl -sSL https://install.python-poetry.org/ | python3 -
```
3. Navigate to your project directory
```
cd /path/to/your/total-replay-project
```
4. Create a virtual environment and activate it
```
poetry shell
```
5. Install project dependencies

6. In total_replay->configuration->config.yml, add the folder path of the Splunk Attack Data repo and the detection folder path in Splunk Security Content.

```
settings:
  security_content_detection_path: ~/path/to/your/security_content/detections
  attack_data_dir_path: ~/path/to/your/attack_data
```
7. make sure you setup the required environment variables for splunk server connection

    | Environment Variables.     | Description             |
    |----------------------------|-------------------------|
    | **SPLUNK_HOST**            | SPLUNK HOST IP ADDRESS  |
    | **SPLUNK_HEC_TOKEN**       | SPLUNK SERVER HEC TOKEN |

    you can use the `export` commandline function for adding these environment variables

    ```
    export SPLUNK_HOST= <IP_ADDRESS>
    export SPLUNK_HEC_TOKEN= <SPLUNK_HEC_TOKEN>
    ```

### Windows
We recommend using the Windows Subsystem for Linux (WSL). You can find a tutorial [here](https://learn.microsoft.com/en-us/windows/wsl/install). After installing WSL, you can follow the steps described in the Linux section.


## Usage

![TOTAL-REPLAY-USAGE](assets/usage.png)

### Features

A. This tool accepts the following types of metadata as input:

    - **Splunk detection names**
    - **MITRE ATT&CK tactic and technique IDs**
    - **Splunk detection GUIDs**
    - **Analytic stories**

It then uses these inputs to identify and replay the attack data associated with them.

B. Or for automation purposes, you can use a simple .txt file like:

```
wsreset_uac_bypass.yml
wscript_or_cscript_suspicious_child_process.yml
windows_user_deletion_via_net.yml
Windows User Disabled Via Net
Windows Chromium Browser No Security Sandbox Process
004e32e2-146d-11ec-a83f-acde48001122
01d29b48-ff6f-11eb-b81e-acde48001123
#T1014
T1589.001
Amos Stealer
PromptLock
f64579c0-203f-11ec-abcc-acde48001122
004e32e2-146d-11ec-a83f-acde48001122  
```

 that contains all the Security Content metadata you want to replay and then choose if you want to replay them all 
