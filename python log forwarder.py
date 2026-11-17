
import json
import os

from azure.identity import ClientSecretCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError

WAZUH_ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]

DCE_ENDPOINT = os.environ["DATA_COLLECTION_ENDPOINT"]
DCR_RULE_ID = os.environ["LOGS_DCR_RULE_ID"]
DCR_STREAM_NAME = os.environ["LOGS_DCR_STREAM_NAME"]

def get_latest_failed_login():

    latest_alert = None

    with open(WAZUH_ALERT_FILE, "r") as file:

        for line in file:

            try:
                alert = json.loads(line)

                rule_id = str(
                    alert.get("rule", {}).get("id", "")
                )

                event_id = str(
                    alert.get("data", {})
                    .get("win", {})
                    .get("system", {})
                    .get("eventID", "")
                )

                if rule_id == "60122" and event_id == "4625":
                    latest_alert = alert

            except json.JSONDecodeError:
                continue

    return latest_alert

def prepare_record(alert):

    agent = alert.get("agent", {})
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    win = data.get("win", {})
    eventdata = win.get("eventdata", {})
    system = win.get("system", {})
    mitre = rule.get("mitre", {})

    mitre_ids = mitre.get("id", [])

    if isinstance(mitre_ids, list):
        mitre_ids = ",".join(mitre_ids)

    timestamp = alert.get("timestamp", "")

    record = {
        "TimeGenerated": timestamp,
        "timestamp": timestamp,
        "rule_id": str(rule.get("id", "")),
        "rule_level": int(rule.get("level", 0)),
        "description": str(rule.get("description", "")),
        "agent_name": str(agent.get("name", "")),
        "agent_ip": str(agent.get("ip", "")),
        "manager_name": str(
            alert.get("manager", {}).get("name", "")
        ),
        "srcip": str(
            data.get("srcip", eventdata.get("ipAddress", ""))
        ),
        "user": str(
            eventdata.get("targetUserName", data.get("user", ""))
        ),
        "event_id": str(system.get("eventID", "")),
        "mitre_id": str(mitre_ids)
    }

    return record

def main():

    try:

        print("Reading Wazuh alert logs...")

        alert = get_latest_failed_login()

        if not alert:
            print("No matching Windows failed-login alert found.")
            return

        record = prepare_record(alert)

        print("Prepared one Wazuh alert for Azure ingestion.")

        credential = ClientSecretCredential(
            tenant_id=TENANT_ID,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET
        )

        client = LogsIngestionClient(
            endpoint=DCE_ENDPOINT,
            credential=credential
        )

        client.upload(
            rule_id=DCR_RULE_ID,
            stream_name=DCR_STREAM_NAME,
            logs=[record]
        )

        print("SUCCESS: One Wazuh alert submitted to Azure.")

        client.close()

    except HttpResponseError as error:
        print(f"Azure ingestion error: {error}")

    except Exception as error:
        print(f"Error: {error}")

if __name__ == "__main__":
    main()
