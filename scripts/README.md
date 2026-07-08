# Attack Data → Splunk Detection Pipeline

A three-stage pipeline that validates [Splunk security_content](https://github.com/splunk/security_content)
detections against [attack_data](https://github.com/splunk/attack_data) datasets and
exports only the events that actually produced detection results.

1. **upload** – Each dataset log file is split line-by-line. Every line becomes an
   individual event with its own freshly generated UUID, uploaded to Splunk HEC with
   that UUID as the `host` field. The UUID map is stored in **DynamoDB**.
2. **detect** – security_content detections are run against the uploaded data. Each
   detection's SPL is rewritten so that `host` is an output field, so we learn exactly
   which uploaded events triggered it. Matches are attributed back to their attack data
   file and stored in DynamoDB.
3. **export** – Only the events that produced detection results are exported using
   `index=<index> host IN (uuid1, uuid2, ...)`, written one file per dataset as
   `<dataset_name>_<attack_data_uuid>.log`.

## Why per-event UUIDs?

Every uploaded event gets a unique `host` UUID. When a detection fires, the `host`
values in its results tell us precisely which source events matched — enabling a
targeted export of just the "interesting" data instead of the entire dataset.

## Files

| File | Purpose |
| --- | --- |
| `migrate.py` | CLI entry point with `upload`, `run`, and `export` subcommands |
| `detection_utils.py` | Discover/parse detection YAML + rewrite SPL to output `host` |
| `splunk_search.py` | Run detections over the Splunk REST API + export raw events |
| `dynamo_utils.py` | DynamoDB store (replaces the old filesystem UUID map) |
| `requirements.txt` | Python dependencies |

## Installation

```bash
pip install -r scripts/requirements.txt
```

Dependencies: `requests`, `urllib3`, `pyyaml`, `splunk-sdk`, `boto3`.

You also need a local clone of security_content for the detections:

```bash
git clone https://github.com/splunk/security_content.git
```

> **Note:** The detections reference security_content macros and lookups (e.g.
> `` `sysmon` ``, `` `security_content_summariesonly` ``, `` `<name>_filter` ``). The
> corresponding app (e.g. ESCU / a `contentctl` build of security_content) must be
> installed on the Splunk instance, otherwise the searches will error. Detections whose
> searches fail are logged and skipped; the run continues.

## DynamoDB table setup

The pipeline stores its UUID map and detection results in a single DynamoDB table.
Create it once, manually.

### Schema

| Attribute | Type | Role |
| --- | --- | --- |
| `pk` | String | Partition key |
| `sk` | String | Sort key |

- **Billing mode:** `PAY_PER_REQUEST` (on-demand) is recommended.
- **No secondary indexes** are required.

### Create with the AWS CLI

```bash
aws dynamodb create-table \
  --table-name attack_data_map \
  --attribute-definitions \
      AttributeName=pk,AttributeType=S \
      AttributeName=sk,AttributeType=S \
  --key-schema \
      AttributeName=pk,KeyType=HASH \
      AttributeName=sk,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST \
  --region <your-region>
```

Wait until the table is active:

```bash
aws dynamodb wait table-exists --table-name attack_data_map --region <your-region>
```

### Create in the AWS Console

1. Open **DynamoDB → Tables → Create table**.
2. **Table name:** `attack_data_map`
3. **Partition key:** `pk` (String)
4. **Sort key:** `sk` (String)
5. **Table settings:** choose *Customize settings* → **Capacity mode:** *On-demand*.
6. Create table.

### Item layout

Uploads and detection results for the same attack data file share the same partition
key, so a single query on `pk` returns everything about that file. UUID lists are
chunked (5,000 per item) to stay under DynamoDB's 400 KB item-size limit.

**Upload record**

```
pk = ATTACK_DATA#<attack_data_uuid>
sk = DATASET#<dataset_name>#<chunk_index>
record_type      = upload
attack_data_uuid, attack_data_file, dataset_name,
source, sourcetype, index_name, chunk_index, event_count,
event_uuids      = [<uuid>, ...]
```

**Detection result record**

```
pk = ATTACK_DATA#<attack_data_uuid>
sk = DETECTION#<detection_id>#<chunk_index>
record_type        = detection_result
attack_data_uuid, detection_id, detection_name, detection_file,
chunk_index, matched_count, updated_at,
matched_host_uuids = [<uuid>, ...]
```

### AWS credentials

`boto3` uses the standard AWS credential chain (environment variables, shared
credentials file, or an IAM role). The identity needs
`dynamodb:PutItem`, `dynamodb:BatchWriteItem`, `dynamodb:Query`, and
`dynamodb:Scan` on the table.

## Configuration

CLI flags override environment variables.

| Variable | Flag | Default | Used by |
| --- | --- | --- | --- |
| `SPLUNK_HOST` | `--host` | – (required) | all |
| `SPLUNK_HEC_TOKEN` | `--hec-token` | – (required) | upload |
| `SPLUNK_HEC_PORT` | `--hec-port` | `8088` | upload |
| `SPLUNK_USERNAME` | `--username` | – (required) | detect/export |
| `SPLUNK_PASSWORD` | `--password` | – (required) | detect/export |
| `SPLUNK_PORT` | `--mgmt-port` | `8089` | detect/export |
| `DYNAMODB_TABLE` | `--dynamodb-table` | `attack_data_map` | all |
| `AWS_REGION` | `--aws-region` | (boto3 default) | all |

```bash
export SPLUNK_HOST="192.168.1.100"
export SPLUNK_HEC_TOKEN="00000000-0000-0000-0000-000000000000"
export SPLUNK_USERNAME="admin"
export SPLUNK_PASSWORD="changeme"
export DYNAMODB_TABLE="attack_data_map"
export AWS_REGION="us-east-1"
```

## Usage

### Full pipeline (upload → detect → export → cleanup)

The `run` command runs in four stages:

1. **Upload** every attack data file (and all of their datasets) to the index.
   Each event line gets its own UUID (used as the Splunk `host`) recorded in
   DynamoDB against its attack data file and dataset.
2. **Detect** — run every detection once over the whole index.
3. **Attribute & export** — for each detection hit, the matched `host` UUIDs are
   mapped back to the attack data file and dataset they came from (via the
   DynamoDB UUID map). Only events with detection hits are exported, one file
   per dataset.
4. **Cleanup** — once everything is detected and exported, delete the uploaded
   data from the index with `index=<index> | delete`, then clear all items from
   the DynamoDB table so the next run starts fresh.

Splunk index cleanup is on by default and requires a Splunk user with the
`can_delete` capability. Disable it with `--no-delete`. Index cleanup is
automatically skipped when `--skip-upload` is used (nothing was re-uploaded in
that run). DynamoDB cleanup is also on by default; disable it with
`--no-clear-dynamodb` if you need to keep the UUID map for a later `export`.

Single attack data file + single detection:

```bash
python scripts/migrate.py run \
  --attack-data datasets/malware/qakbot/qakbot.yml \
  --detection ~/security_content/detections/endpoint/some_detection.yml \
  --export-dir exported
```

Whole folders (searched recursively):

```bash
python scripts/migrate.py run \
  --attack-data datasets/malware/qakbot \
  --detection ~/security_content/detections/endpoint \
  --export-dir exported
```

Re-run detections without re-uploading (reuses UUIDs already in DynamoDB):

```bash
python scripts/migrate.py run \
  --attack-data datasets/malware/qakbot \
  --detection ~/security_content/detections/endpoint \
  --skip-upload
```

Keep the uploaded data in the index after the run (skip the final cleanup):

```bash
python scripts/migrate.py run \
  --attack-data datasets/malware/qakbot \
  --detection ~/security_content/detections/endpoint \
  --export-dir exported \
  --no-delete
```

### Upload only

```bash
python scripts/migrate.py upload --attack-data datasets/malware/qakbot
```

### Export previously matched events

Reads all uploads and detection-matched host UUIDs from DynamoDB and exports
them, one file per dataset:

```bash
python scripts/migrate.py export --export-dir exported
```

### Exported files

Export is **per dataset**. An attack data file that defines multiple datasets
has all of its datasets uploaded, and each dataset is exported into its own
file. The filename combines the dataset name and the attack data file UUID:

```
<export-dir>/<dataset_name>_<attack_data_uuid>.log
```

For example, `datasets/attack_techniques/T1003.002/atomic_red_team/atomic_red_team.yml`
(UUID `cc9b25e7-...`) with datasets `crowdstrike_falcon` and `windows-sysmon`
produces:

```
exported/crowdstrike_falcon_cc9b25e7-efc9-11eb-926b-550bf0943fbb.log
exported/windows-sysmon_cc9b25e7-efc9-11eb-926b-550bf0943fbb.log
```

Only events that produced detection results are written.

### Updating the attack data in place (`--update-attack-data`)

With `--update-attack-data` (available on `run` and `export`), the curated
per-dataset logs are additionally written **into the attack data YAML's own
folder**, and the YAML is updated:

- `date` is set to today.
- the `datasets` section is rewritten to point at the curated files
  (`<dataset_name>_<attack_data_uuid>.log` in the same folder). Datasets that
  produced no detection matches are dropped.

```bash
python scripts/migrate.py run \
  --attack-data datasets/malware/qakbot \
  --detection ~/security_content/detections/endpoint \
  --update-attack-data
```

This effectively minimizes a dataset down to only the events that trigger
detections and updates the YAML to describe the curated data. It can be combined
with `--export-dir`, or used on its own. The original log files are left on disk
(the YAML simply stops referencing them), so review/commit the changes with git.

### Updating detection tests (`--update-detection-tests`)

With `--update-detection-tests` (available on `run` and `export`), each detection
YAML's `tests` section is rewritten to reference the attack data that matched
**that specific detection**. For every matched dataset, an `attack_data` entry is
added using the standard GitHub URL format:

```yaml
tests:
    - name: True Positive Test
      attack_data:
        - data: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/...
          source: ...
          sourcetype: ...
```

The detection's `date` field is also set to today. Detections with no matches are
left unchanged and a warning is printed. Run this after `--update-attack-data` if
you want the tests to point at the curated log files.

At the end of each `run`, a **DETECTIONS NOT UPDATED** summary lists every
detection whose tests were not updated, with the reason (`no matches`,
`search failed`, etc.). When `--update-detection-tests` is enabled, any detection
not successfully written is included.

```bash
python scripts/migrate.py run \
  --attack-data datasets/attack_techniques/T1003.001/atomic_red_team \
  --detection scripts/detection_tests \
  --update-attack-data \
  --update-detection-tests
```

## How detections are rewritten to output `host`

`add_host_output_field()` in `detection_utils.py` rewrites the SPL so the `host` field
survives to the output:

- `stats` / `tstats` / `eventstats` / `streamstats` / `sistats`: `host` is appended to
  the `by` clause (or `by host` is added when there is none).
- `table` / `fields`: `host` is appended to the projected field list.
- Raw (non-aggregating) searches already carry `host` through.

Pipe-splitting is quote- and bracket-aware, so subsearches, quoted strings, and `eval`
expressions are not broken.

Example:

```
| tstats count from datamodel=Endpoint.Processes by Processes.dest
   ⇒ | tstats count from datamodel=Endpoint.Processes by Processes.dest, host
```

## Notes & assumptions

- **Search time window** defaults to all-time (`earliest=0`) because attack data
  timestamps can be years old. Override with `--earliest` / `--latest`.
- **TLS verification** is disabled by default (`--verify-tls` for HEC uploads,
  `--verify-ssl` for searches enable it).
- Matched hosts are intersected with the UUIDs actually uploaded in the run, so
  pre-existing data in the target index is ignored during attribution.
- The target index defaults to `test` (`--index` to change).
```
