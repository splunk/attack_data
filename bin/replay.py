import argparse
import sys
import yaml
import os
import re
import io
import json
import fileinput
from datetime import datetime
from datetime import timedelta
import splunklib.client as client


class DataManipulation:

    def manipulate_timestamp(self, file_path, sourcetype, source):
        source = source.lower()
        sourcetype = sourcetype.lower()

        # check that we support the source or sourcetype sent for manipulation
        SUPPORTED = ['XmlWinEventLog:Microsoft-Windows-Sysmon/Operational', 'WinEventLog:System', 'WinEventLog:Security', 'exchange', 'aws:cloudtrail']
        SUPPORTED = list(map(lambda x: x.lower(), SUPPORTED))
        if (sourcetype in SUPPORTED) or (source in SUPPORTED):
            print("updating timestamps before replaying for file: {0}".format(file_path))
        else:
            print("WARNING - cannot manipulate the timestamp for file: {0}, sourcetype: `{1}` or source: `{2}` it is not currently supported.".format(file_path, sourcetype, source))
            return

        if sourcetype == 'aws:cloudtrail':
            self.manipulate_timestamp_cloudtrail(file_path)

        if source == 'WinEventLog:System'.lower() or source == 'WinEventLog:Security'.lower():
            self.manipulate_timestamp_windows_event_log_raw(file_path)
        
        if source == 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational'.lower():
            self.manipulate_timestamp_windows_sysmon_log_raw(file_path)

        if source == 'exchange':
            self.manipulate_timestamp_exchange_logs(file_path)


    def manipulate_timestamp_exchange_logs(self, file_path):
        f = io.open(file_path, "r", encoding="utf-8")
        first_line = f.readline()
        d = json.loads(first_line)
        latest_event  = datetime.strptime(d["CreationTime"],"%Y-%m-%dT%H:%M:%S")

        now = datetime.now()
        now = now.strftime("%Y-%m-%dT%H:%M:%S")
        now = datetime.strptime(now,"%Y-%m-%dT%H:%M:%S")

        difference = now - latest_event
        f.close()

        for line in fileinput.input(path, inplace=True):
            d = json.loads(line)
            original_time = datetime.strptime(d["CreationTime"],"%Y-%m-%dT%H:%M:%S")
            new_time = (difference + original_time)

            original_time = original_time.strftime("%Y-%m-%dT%H:%M:%S")
            new_time = new_time.strftime("%Y-%m-%dT%H:%M:%S")
            print (line.replace(original_time, new_time),end ='')


    def manipulate_timestamp_windows_event_log_raw(self, file_path):
        f = io.open(file_path, "r", encoding="utf-8")
        self.now = datetime.now()
        self.now = self.now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self.now = datetime.strptime(self.now,"%Y-%m-%dT%H:%M:%S.%fZ")

        # read raw logs
        regex = r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M'
        data = f.read()
        lst_matches = re.findall(regex, data)
        if len(lst_matches) > 0:
            latest_event  = datetime.strptime(lst_matches[-1],"%m/%d/%Y %I:%M:%S %p")
            self.difference = self.now - latest_event
            f.close()

            result = re.sub(regex, self.replacement_function, data)

            with io.open(file_path, "w+", encoding='utf8') as f:
                f.write(result)
        else:
            f.close()
            return

    def manipulate_timestamp_windows_sysmon_log_raw(self, file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            
            regex4systemTime = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' # <TimeCreated SystemTime="2021-04-05T14:11:22.091374000Z"/>
            regex4utcTime = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}' # <Data Name="UtcTime">2021-04-05 14:11:22.089</Data>  

            format4systemTime = "%Y-%m-%dT%H:%M:%S"
            format4utcTime = "%Y-%m-%d %H:%M:%S.%f"

            systemTimes = re.findall(regex4systemTime, content)
            utcTimes = re.findall(regex4utcTime, content)

            systemTimes.sort()
            utcTimes.sort()

            # Difference for systemTime
            now = datetime.now().strftime(format4systemTime)
            now = datetime.strptime(now, format4systemTime)
            last_event_time  = datetime.strptime(systemTimes[-1],format4systemTime)
            time_difference_4_systemTime = now - last_event_time

            # Difference for utcTime
            now = datetime.now().strftime(format4utcTime)
            now = datetime.strptime(now, format4utcTime)
            last_event_time  = datetime.strptime(utcTimes[-1],format4utcTime)
            time_difference_4_utcTime = now - last_event_time

            # re.sub replacement function for systemTimes
            def replacement_func_4_systemTime(m):
                updated_systemTime = datetime.strptime(m.group(), format4systemTime) + time_difference_4_systemTime
                updated_systemTime = updated_systemTime.strftime(format4systemTime)
                return updated_systemTime
            
            # re.sub replacement function for utcTimes
            def replacement_func_4_utcTime(m):
                updated_utcTime = datetime.strptime(m.group(), format4utcTime) + time_difference_4_utcTime
                updated_utcTime = updated_utcTime.strftime(format4utcTime)
                return updated_utcTime


            content = re.sub(regex4systemTime, replacement_func_4_systemTime, content)
            content = re.sub(regex4utcTime, replacement_func_4_utcTime, content)
            with open('regex.log', 'w+', encoding='utf8') as write_file:
                write_file.write(file_path)
                print("Timestamps successfully updated.")

    def replacement_function(self, match):
        try:
            event_time = datetime.strptime(match.group(),"%m/%d/%Y %I:%M:%S %p")
            new_time = self.difference + event_time
            return new_time.strftime("%m/%d/%Y %I:%M:%S %p")
        except Exception as e:
            print("ERROR - in timestamp replacement occured: " + str(e))
            return match.group()

        f = io.open(file_path, "r", encoding="utf-8")

        try:
            first_line = f.readline()
            d = json.loads(first_line)
            latest_event  = datetime.strptime(d["eventTime"],"%Y-%m-%dT%H:%M:%S.%fZ")

            now = datetime.now()
            now = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            now = datetime.strptime(now,"%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            first_line = f.readline()
            d = json.loads(first_line)
            latest_event  = datetime.strptime(d["eventTime"],"%Y-%m-%dT%H:%M:%SZ")

            now = datetime.now()
            now = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            now = datetime.strptime(now,"%Y-%m-%dT%H:%M:%SZ")

        difference = now - latest_event
        f.close()

        for line in fileinput.input(file_path, inplace=True):
            try:
                d = json.loads(line)
                original_time = datetime.strptime(d["eventTime"],"%Y-%m-%dT%H:%M:%S.%fZ")
                new_time = (difference + original_time)

                original_time = original_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                new_time = new_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                print (line.replace(original_time, new_time),end ='')
            except ValueError:
                d = json.loads(line)
                original_time = datetime.strptime(d["eventTime"],"%Y-%m-%dT%H:%M:%SZ")
                new_time = (difference + original_time)

                original_time = original_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                new_time = new_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                print (line.replace(original_time, new_time),end ='')


def send_to_splunk(settings):
    # connect to splunk
    try:
        service = client.connect(host=settings['splunk']['host'], port=8089, username=settings['splunk']['username'], password=settings['splunk']['password'])
    except ConnectionRefusedError as e:
        print("ERROR - could not connect to the splunk server {}:8089".format(settings['splunk']['host']))
        sys.exit(1)

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

            # update timestamps before replay
            if 'update_timestamp' in dataset['replay_parameters']:
                    if dataset['replay_parameters']['update_timestamp'] == True:
                        data_manipulation = DataManipulation()
                        data_manipulation.manipulate_timestamp(fullpath, dataset['replay_parameters']['sourcetype'], dataset['replay_parameters']['source'])

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
