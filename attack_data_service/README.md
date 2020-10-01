# Attack Data Service
The attack data service allows you to run attacks using the [Attack Range](https://github.com/splunk/attack_range) as a service and the attack data will be collected.

## Architecture
![Architecture](attack_data_service/static/architecture_attack_data_service.png)
The attack data service is using AWS Batch as execution engine. AWS batch allows you to run batch computing jobs, in our case the attack range for attack data generation. attack_data_service.py is the executable which controls the attack range execution. This executable is deployed in a docker container which is used by AWS Batch.


## Usage
```
python attack_data_service.py
usage: attack_data_service.py [-h] -st SIMULATION_TECHNIQUE
                              [-sa SIMULATION_ATOMIC]
                              [-arr ATTACK_RANGE_REPO]
                              [-arb ATTACK_RANGE_BRANCH]
                              [-adr ATTACK_DATA_REPO]
                              [-adb ATTACK_DATA_BRANCH]
                              [-artr ATOMIC_RED_TEAM_REPO]
                              [-artb ATOMIC_RED_TEAM_BRANCH]
                              [-gt GITHUB_TOKEN] [-smk SECRETS_MANAGER_KEY]
attack_data_service.py: error: the following arguments are required: -st/--simulation_technique
```

The attack_data_service.py has one mandatory parameter, which is --simulation_technique. Simulation technique expects a technique id form the Mitre ATT&CK Matrix with corresponding tests in [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), e.g. T1003.002. The other parameters are optional and can be used to specify forks of projects or specific branches. The attack_data_service.py is creating Pull Requests after a successful test. Therefore, it needs a Github OAUTH Token. This can be either added with the parameter --github_token or can be derived from the [AWS secrets manager](https://aws.amazon.com/secrets-manager/) through --secrets_manager_key.

Let's have a look how to use the attack data service after you deployed it:

### Using AWS CLI

Example 1:
```
aws batch submit-job --job-name attack_data_T1003_001 --job-definition attack_data_service_job --job-queue attack_data_service_queue --container-overrides '{"command": ["-st", "T1003.002"]}'
```

Example 2:
```
aws batch submit-job --job-name attack_data_T1003_001 --job-definition attack_data_service_job --job-queue attack_data_service_queue --container-overrides '{"command": ["-st", "T1003.001", "-sa", "Dump LSASS.exe Memory using comsvcs.dll", "-adr", "P4T12ICK/attack-data", "-adb", "develop", "-smk", "github_token"]}'
```

### Using AWS Web Portal
The Attack Data Generation Service can be also triggered over the AWS Web Portal. You will first click on the service "Batch" and then click on the left side "Jobs". Then, you click on "submit new job". You will fill the variables according to the following screenshot and click on "Submit".
![AWS Batch Job](attack_data_service/static/aws_batch_submit_job.png)

## Deployment
In order to deploy the Attack Data Generation Service to AWS Batch, please follow this guideline. This description assumes that you will deploy the Attack Data Generation Service to the region eu-central-1.

### Prerequisites
- AWS account
- IAM user with administrative permissions
- AWS CLI
- Docker
- Attack Data Project Fork

### Create GitHub Token


### Upload GitHub Token to AWS Secrets Manager


### Build and Upload Docker File
- Navgigate to the attack_data_service folder:
```
cd attack_data_service
```
- Build the docker container
```
docker build --tag awsbatch/attack-data-service .
```


### Create AWS ECR Repository


### Configure AWS Batch

- Configure AWS Batch based on the following tutorial https://stackify.com/aws-batch-guide/ and the docker file.
