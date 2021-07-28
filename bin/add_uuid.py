import yaml
import sys
import argparse
import uuid
from os import path, walk

def add_uuid(REPO_PATH, content_part, VERBOSE):
    manifest_files = []

    types = ["attack_techniques", "malware", "suspicious_behaviour"]
    for t in types:
        for root, dirs, files in walk(REPO_PATH + "/" + content_part + '/' + t):
            for file in files:
                if file.endswith(".yml"):
                    manifest_files.append((path.join(root, file)))

    for manifest_file in manifest_files:
        pretty_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue

        pretty_yaml['author'] = object['author']
        pretty_yaml['id'] = str(uuid.uuid1())
        pretty_yaml['date'] = object['date']
        pretty_yaml['description'] = object['description']
        pretty_yaml['environment'] = object['environment']
        pretty_yaml['dataset'] = object['dataset']
        pretty_yaml['sourcetypes'] = object['sourcetypes']
        if 'references' in object:
            pretty_yaml['references'] = object['references']
        else:
            pretty_yaml['references'] = []

        with open(manifest_file, 'w') as file:
            documents = yaml.dump(pretty_yaml, file, sort_keys=False)

    return manifest_files

def main(args):
    parser = argparse.ArgumentParser(description="adds uuid")
    parser.add_argument("-p", "--path", required=True, help="path to security_content repo")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")

    args = parser.parse_args()
    REPO_PATH = args.path
    VERBOSE = args.verbose
    output = []
    content_part = 'datasets'
    manifest_files = add_uuid(REPO_PATH, content_part, VERBOSE)

    print("process {0} attack data files".format(len(manifest_files)))


if __name__ == "__main__":
    main(sys.argv[1:])
