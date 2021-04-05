import argparse
import sys
import yaml

def main(CONFIG_PATH, VERBOSE):
    with open(CONFIG_PATH, 'r') as stream:
        try:
            settings = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            print("ERROR: reading configuration file {0}".format(CONFIG_PATH))
            sys.exit(1)

    print(settings)


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
    main(CONFIG_PATH, verbose)
