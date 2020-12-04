import os
from os import path
import sys
import argparse
import git
from shutil import copyfile
from shutil import which
import subprocess
import boto3
from random import randrange
import yaml
from github import Github
from jinja2 import Environment, FileSystemLoader
import base64
from botocore.exceptions import ClientError
import json
from datetime import datetime
import time
import shutil
from os import listdir
from os.path import isfile, join



def main(args):

    parser = argparse.ArgumentParser(description="attack data service based on Attack Range.")
    parser.add_argument("-st", "--simulation_technique", required=True,
                        help="specify the simulation technique to execute")
    parser.add_argument("-sa", "--simulation_atomics", required=False, default="none",
                        help="specify a specific atomics to simulate")
    parser.add_argument("-arr", "--attack_range_repo", required=False, default="splunk/attack_range",
                        help="specify the url of the atack range repository")
    parser.add_argument("-arb", "--attack_range_branch", required=False, default="develop",
                        help="specify the atack range branch")
    parser.add_argument("-adr", "--attack_data_repo", required=False, default="splunk/attack_data",
                        help="specify the url of the attack data repository")
    parser.add_argument("-adb", "--attack_data_branch", required=False, default="master",
                        help="specify the attack data branch")
    parser.add_argument("-artr", "--atomic_red_team_repo", required=False, default="splunk",
                        help="specify the url of the attack data repository")
    parser.add_argument("-artb", "--atomic_red_team_branch", required=False, default="local-master",
                        help="specify the attack data branch")
    parser.add_argument("-gt", "--github_token", required=False,
                        help="specify the github token for the PR")
    parser.add_argument("-smk", "--secrets_manager_key", required=False, default="github_token",
                        help="specify the key in AWS secrets manager for your github token")
    parser.add_argument("-sbu", "--s3_bucket_url", required=False, default="https://attack-range-attack-data.s3-us-west-2.amazonaws.com",
                        help="specify the S3 bucket to store the Attack Data")


    args = parser.parse_args()
    simulation_technique = args.simulation_technique
    simulation_atomics = args.simulation_atomics
    attack_range_repo = args.attack_range_repo
    attack_range_branch = args.attack_range_branch
    attack_data_repo = args.attack_data_repo
    attack_data_branch = args.attack_data_branch
    atomic_red_team_repo = args.atomic_red_team_repo
    atomic_red_team_branch = args.atomic_red_team_branch
    github_token = args.github_token
    secrets_manager_key = args.secrets_manager_key
    s3_bucket_url = args.s3_bucket_url

    # get github token
    if github_token:
        O_AUTH_TOKEN_GITHUB = github_token
    else:
        O_AUTH_TOKEN_GITHUB = get_secret(secrets_manager_key)

    # clone repositories
    git.Repo.clone_from('https://github.com/' + attack_range_repo, "attack_range", branch=attack_range_branch)
    attack_data_repo_obj = git.Repo.clone_from('https://' + O_AUTH_TOKEN_GITHUB + ':x-oauth-basic@github.com/' + attack_data_repo, "attack_data", branch=attack_data_branch)

    sys.path.append(os.path.join(os.getcwd(),'attack_range'))
    copyfile('attack_range/attack_range.conf.template', 'attack_range/attack_range.conf')

    epoch_time = str(int(time.time()))
    ssh_key_name = 'ads-key-pair-' + epoch_time
    # create ssh keys
    ec2 = boto3.client('ec2')
    response = ec2.create_key_pair(KeyName=ssh_key_name)
    with open(ssh_key_name, "w") as ssh_key:
        ssh_key.write(response['KeyMaterial'])
    os.chmod(ssh_key_name, 0o600)


    with open('attack_range/attack_range.conf', 'r') as file :
      filedata = file.read()

    filedata = filedata.replace('attack_range_password = Pl3ase-k1Ll-me:p', 'attack_range_password = I-l1ke-Attack-Range!')
    filedata = filedata.replace('region = us-west-2', 'region = eu-central-1')
    filedata = filedata.replace('art_repository = splunk', 'art_repository = ' + atomic_red_team_repo)
    filedata = filedata.replace('art_branch =  local-master', 'art_branch = ' + atomic_red_team_branch)
    filedata = filedata.replace('key_name = attack-range-key-pair', 'key_name = ' + ssh_key_name)
    filedata = filedata.replace('private_key_path = ~/.ssh/id_rsa', 'private_key_path = /app/' + ssh_key_name)

    with open('attack_range/attack_range.conf', 'w') as file:
      file.write(filedata)

    # check if terraform is installed
    if which('terraform') is None:
        sys.exit(1)
    else:
        # init terraform
        os.system('cd attack_range/terraform/aws && terraform init && cd ../../..')

    module = __import__('attack_range')
    module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'build']

    execution_error = False

    # build Attack Range
    try:
        results_build = module.main(module.sys.argv)
    except Exception as e:
        print('Error: ' + str(e))
        module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'destroy']
        module.main(module.sys.argv)
        execution_error = True

    # simulate Technique
    if simulation_atomics == 'none':
        module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'simulate', '-st', simulation_technique, '-t', str('ar-win-dc-default-' + ssh_key_name)]
    else:
        module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'simulate', '-st', simulation_technique, '-t', str('ar-win-dc-default-' + ssh_key_name), '--simulation_atomics', simulation_atomics]

    try:
        results_simulate = module.main(module.sys.argv)
    except Exception as e:
        print('Error: ' + str(e))
        module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'destroy']
        module.main(module.sys.argv)
        execution_error = True

    # wait
    print('Wait for 200 seconds')
    time.sleep(200)

    # dump attack data
    module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'dump', '--dump_name', simulation_technique]
    try:
        results_dump = module.main(module.sys.argv)
    except Exception as e:
        print('Error: ' + str(e))
        module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'destroy']
        module.main(module.sys.argv)
        execution_error = True

    # destroy Attack Range
    module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'destroy']
    try:
        results_destroy = module.main(module.sys.argv)
    except Exception as e:
        print('Error: ' + str(e))
        module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'destroy']
        module.main(module.sys.argv)
        execution_error = True

    # delete ssh key
    response = ec2.delete_key_pair(KeyName=ssh_key_name)

    # check if was succesful
    if not execution_error:

        random_number = epoch_time

        # Create GitHub PR attack data
        branch_name = "attack_data_service_" + random_number
        attack_data_repo_obj.git.checkout(attack_data_branch, b=branch_name)

        dataset_obj = {}
        dataset_obj['author'] = 'Automated Attack Data Service'
        dataset_obj['date'] = str(datetime.today().strftime('%Y-%m-%d'))
        descr_str = 'Atomic Test Results: '
        for output in results_simulate:
            descr_str += output + ' '

        dataset_obj['description'] = descr_str
        dataset_obj['environment'] = 'attack_range'
        dataset_obj['technique'] = [simulation_technique]

        #list files
        mypath = 'attack_range/attack_data/' + simulation_technique
        onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]

        #copy files from dump
        parent_folder = 'attack_data/datasets/attack_techniques/' + simulation_technique
        if not path.exists(parent_folder):
            os.mkdir(parent_folder)

        folder = 'attack_data/datasets/attack_techniques/' + simulation_technique + '/atomic_red_team'
        if not path.exists(folder):
            os.mkdir(folder)

        for f in onlyfiles:
            shutil.copy(mypath + '/' + f, folder + '/' + f)
            attack_data_repo_obj.index.add(['datasets/attack_techniques/' + simulation_technique + '/atomic_red_team/' + f])

        dataset_urls = []
        for file in onlyfiles:
            dataset_urls.append('https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/' + simulation_technique +  '/atomic_red_team/' + file)

        dataset_obj['dataset'] = dataset_urls
        dataset_obj['references'] = ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/' + simulation_technique + '/' + simulation_technique + '.md']
        dataset_obj['sourcetypes'] = ['XmlWinEventLog:Microsoft-Windows-Sysmon/Operational', 'WinEventLog:Microsoft-Windows-PowerShell/Operational', 'WinEventLog:System', 'WinEventLog:Security']


        if simulation_atomics == 'none':
            with open(folder + '/atomic_red_team.yml', 'w+' ) as outfile:
    	           yaml.dump(dataset_obj, outfile , default_flow_style=False, sort_keys=False)
            attack_data_repo_obj.index.add(['datasets/attack_techniques/' + simulation_technique + '/atomic_red_team/atomic_red_team.yml'])
        else:
            filename = simulation_atomics.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower() + '.yml'
            with open(folder + '/' + filename, 'w+' ) as outfile:
    	           yaml.dump(dataset_obj, outfile , default_flow_style=False, sort_keys=False)
            attack_data_repo_obj.index.add(['datasets/attack_techniques/' + simulation_technique + '/atomic_red_team/' + filename])

        attack_data_repo_obj.index.commit('Added attack data')

        j2_env = Environment(loader=FileSystemLoader('templates'),trim_blocks=True)
        template = j2_env.get_template('PR_template_attack_data.j2')
        body = template.render()

        attack_data_repo_obj.git.push('--set-upstream', 'origin', branch_name)
        g = Github(O_AUTH_TOKEN_GITHUB)
        repo = g.get_repo("splunk/attack_data")
        pr = repo.create_pull(title="Attack Data Service PR " + random_number, body=body, head=branch_name, base="master")



def load_file(file_path):
    with open(file_path, 'r') as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def get_secret(secret_name):

    region_name = "eu-central-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            secret_obj = json.loads(secret)

    return secret_obj['github_token']


if __name__ == "__main__":
    main(sys.argv[1:])
