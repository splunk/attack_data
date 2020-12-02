import yaml
import glob
import os
import sys
import requests
import argparse
from os import path, walk
from pathlib import Path
import pathlib
from urllib.parse import urlparse


def load_file(file_path):
    with open(file_path, 'r', encoding="utf-8") as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def write_file(obj, file_path):
    with open(os.path.join(os.path.dirname(__file__), '../datasets/', file_path), 'w+' ) as outfile:
       yaml.dump(obj, outfile , default_flow_style=False, sort_keys=False)


def write_new_object(obj, relative_path, branch):
    new_obj = obj.copy()
    new_obj['dataset'] = []
    for dataset in obj['dataset']:
        a = urlparse(dataset)
        data_file_name = os.path.basename(a.path)
        new_obj['dataset'].append('https://media.githubusercontent.com/media/splunk/attack_data/' + branch + '/datasets/' + os.path.dirname(relative_path) + '/' + data_file_name)

    write_file(new_obj, relative_path)


def load_objects(relative_path):
    files = []
    objs = []
    manifest_files = os.path.join(os.path.dirname(__file__), '../', relative_path)
    for file in sorted(glob.glob(manifest_files)):
        p = pathlib.Path(file)
        rel_path = str(pathlib.Path(*p.parts[2:]))
        objs.append(load_file(file))
        files.append(rel_path)
    return objs, files


def convert_attack_data_objects(relative_path, branch):
    attack_data_objs, attack_data_files = load_objects(relative_path)

    counter = 0
    for attack_data_obj in attack_data_objs:
        write_new_object(attack_data_obj, attack_data_files[counter], branch)
        counter += 1


def main(args):
    parser = argparse.ArgumentParser(description="changes url links to datasets")
    parser.add_argument("-b", "--branch", required=True, help="new branch")

    args = parser.parse_args()
    branch = args.branch

    convert_attack_data_objects('datasets/attack_techniques/*/*/*.yml', branch)
    convert_attack_data_objects('datasets/malware/*/*.yml', branch)
    convert_attack_data_objects('datasets/suspicious_behaviour/*/*.yml', branch)


if __name__ == "__main__":
    main(sys.argv[1:])
