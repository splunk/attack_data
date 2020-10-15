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
                              [-gt GITHUB_TOKEN]
                              [-smk SECRETS_MANAGER_KEY]
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
The GitHub Token allows the Automate Detection Testing Service to create Pull Requests.
- Create a Personal GitHub Acces Token according to the following [tutorial](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/creating-a-personal-access-token)

### Upload GitHub Token to AWS Secrets Manager
- Connect to AWS Web Portal
- Go to the AWS Secrets Manager
- Choose region eu-central-1
- Click on "Store a new secret"
- Click on "Other type of secrets"
- Add "github_token" as key
- Copy the github token as value
- Click on "Next"
- Use "github_token" as Secret name
- Click on "Next"
- Click on "Next"
- Click on "Store"

### Create AWS ECR Repository
- Connect to AWS Web Portal
- Go to service "Elastic Container Registry"
- Click on "Repositories" under Amazon ECR on the left side.
- Click on "Create repository"
- Add "awsbatch/attack-data-service" as repository name
- Click on "Create repository"

### Build and Upload Docker File
- Navgigate to the attack_data_service folder:
```
cd attack_data_service
```
- Build the docker container
```
docker build --tag awsbatch/attack-data-service .
```
- Tag the docker container (The aws account number can be found in the AWS ECR Repository path)
```
docker tag awsbatch/detection-testing-service:latest [aws_account_number].dkr.ecr.eu-central-1.amazonaws.com/awsbatch/attack-data-service:latest
```
- Login to AWS ECR
```
aws ecr get-login-password --region eu-central-1 | docker login --username AWS --password-stdin [aws_account_number].dkr.ecr.eu-central-1.amazonaws.com
```
- Upload Docker container
```
docker push [aws_account_number].dkr.ecr.eu-central-1.amazonaws.com/awsbatch/attack-data-service:latest
```

### Configure AWS Batch
- Connect to AWS Web Portal
- Go to service "AWS Batch"
- Click on "Compute environments" on the left side
- Click on "Create"
- Use "attack_data_service_environment" as "Compute environment name"
- Define Instance Configuration according to your demand. You can choose small instance types, because the instance will run docker and docker will only run a python script.
- Define the vpc and subnets which you want to use in Networking
- Click on "create compute environment"

- Click on "Job queues" on the left side
- Click on "Create"
- Use "attack_data_service_queue" as "Job queue name"
- Select "attack_data_service_environment" as "compute environment"
- Click on "Create"

- Go to service "IAM"
- Create the following role with name: attack_data_service_role with the Policies AmazonEC2FullAccess, SecretsManagerReadWrite and AmazonS3FullAccess

- Go to service "AWS Batch"
- Click on "Job definitions" on the left side
- Click on "Create"
- Use "attack_data_service" as Name
- Use 3000 as "Execution timeout"
- Container properties:
- Use "[aws_account_number].dkr.ecr.eu-central-1.amazonaws.com/awsbatch/attack_data_service:latest" as Image
- remove Command from Command field
- Use 2 in vCPUs
- Use 2048 in Memory
- Click on "Additional configuration"
- Use "attack_data_service_role" as Job Role
- Use root as "User" under Security
- Click on "Create"

## Local Detection Testing
The Detection Testing Service can be also run locally.
- Navgigate to the attack_data_service folder:
```
cd attack_data_service
```
- Build the docker container
```
docker build --tag awsbatch/attack_data_service .
```
- Run the docker container
```
docker run -v ~/.aws/credentials:/root/.aws/credentials:ro --name attackrange awsbatch/attack_data_service:latest -sa T1003.001  -adr P4T12ICK/attack_data
```

## Troubleshooting
AWS Batch will store the logs in Cloudwatch. Check the cloudwatch logs for Troubleshooting.
