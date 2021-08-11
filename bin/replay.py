import argparse
import sys
import yaml
import os
import splunklib.client as client

def dump(obj):
    for attr in dir(obj):
        print("obj.{0} = {1}".format(attr, getattr(obj, attr)))

def send_to_splunk(settings):
    # connect to splunk
    service = client.connect(host=settings['splunk']['host'], port=8089, username=settings['splunk']['username'], password=settings['splunk']['password'])

    # go through all datasets
    for dataset in settings['datasets']:
        # check dataset is enabled
        if dataset['enabled']:
            # does the index exists?
            if dataset['replay_parameters']['index'] not in service.indexes:
                print("ERROR - index {0} does not exist on splunk server  {1}.".format(dataset['replay_parameters']['index'], settings['splunk']['host']))
                sys.exit(1)
            # set index
            index = service.indexes[dataset['replay_parameters']['index']]
            fullpath = os.path.abspath(dataset['path'])
            # upload file

            kwargs_submit = dict()
            kwargs_submit['sourcetype'] = dataset['replay_parameters']['sourcetype']
            kwargs_submit['rename-source'] = dataset['replay_parameters']['source']
            results = index.upload(fullpath, **kwargs_submit)
    return True

def parse_config(CONFIG_PATH, VERBOSE):
    with open(CONFIG_PATH, 'r') as stream:
        try:
            settings = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            print("ERROR: reading configuration file {0}".format(CONFIG_PATH))
            sys.exit(1)
    return settings


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="replays attack_data datasets into a configured splunk server", epilog="""
        replay.py requires you to have a running splunk instance and username/password set under replay.yml in order to function.""")
    parser.add_argument("-c", "--config", required=False, default="replay.yml",
                        help="path to the configuration file of replay.py, defaults to replay.yml")
    parser.add_argument("-v", "--verbose", required=False, action='store_true', help="prints verbose output")

    # parse them
    args = parser.parse_args()
    CONFIG_PATH = args.config
    verbose = args.verbose
    settings = parse_config(CONFIG_PATH, verbose)
    status = send_to_splunk(settings)

    if status:
        print("successfully indexed {0} dataset on splunk server {1}".format(len(settings['datasets']), settings['splunk']['host']))
    else:
        print("ERROR - issue replaying desired datasets on splunk server {0}".format(settings['splunk']['host']))
