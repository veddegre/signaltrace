# SignalTrace Splunk App

A minimal Splunk app for ingesting and visualising SignalTrace data.

## Installation

Copy the `signaltrace` directory into your Splunk apps folder:

```bash
cp -r signaltrace $SPLUNK_HOME/etc/apps/
```

Then restart Splunk:

```bash
$SPLUNK_HOME/bin/splunk restart
```

## Configuration

### 1. Edit the fetch script

Open `$SPLUNK_HOME/etc/apps/signaltrace/bin/signaltrace_fetch.sh` and set your endpoint and token:

```bash
ENDPOINT="https://yourdomain.example/export/json"
TOKEN="your-generated-token"
```

### 2. Enable the input

Edit `$SPLUNK_HOME/etc/apps/signaltrace/default/inputs.conf` and set `disabled = false`.

Or enable it through the Splunk UI under Settings > Data Inputs > Scripts.

### 3. Verify ingestion

After one poll interval (default 5 minutes), check for data:

```spl
index=security sourcetype=signaltrace | head 10
```

## Dashboard

The `dashboards/signaltrace_overview.json` file is a Dashboard Studio dashboard. To import it:

1. Go to Dashboards in the Splunk UI
2. Click Create New Dashboard
3. Choose Dashboard Studio
4. Use the source editor and paste the contents of `signaltrace_overview.json`

## Troubleshooting

See the [Splunk Integration wiki page](https://github.com/yourusername/signaltrace/wiki/Splunk-Integration) for common issues including the Apache `Authorization` header fix, curl certificate errors in Splunk, and deduplication details.

