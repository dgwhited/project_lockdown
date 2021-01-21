from base64 import b64decode
import json
import logging
import gc

from os import getenv
from googleapiclient.discovery_cache.base import Cache
import googleapiclient.discovery

from lockdown_logging import create_logger # pylint: disable=import-error
# from lockdown_pubsub import publish_message # pylint: disable=import-error
from lockdown_checklist import check_list # pylint: disable=import-error
from lockdown_notify import LockdownFinding, Notify # pylint: disable=import-error

def pubsub_trigger(data, context):
    """
    Used with Pub/Sub trigger method to evaluate firewall rules with 0.0.0.0/0 source ingress.
    """

    # Integrates cloud logging handler to python logging
    create_logger()

    # Converting log to json
    data_buffer = b64decode(data['data'])
    log_entry = json.loads(data_buffer)

    # Parse project id and resource name for allow/deny list checking and remediation
    resource_name = log_entry['protoPayload']['resourceName'].split('/')
    project_id = resource_name[1]
    firewall_name = resource_name[-1]

    if check_list(project_id):
        logging.info(f'The project {project_id} is not in the allowlist, is in the denylist, or a list is not fully configured. Continuing evaluation.')
        check_resource(project_id, firewall_name)
    else:
        logging.info(f'The project {project_id} is in the allowlist or is not in the denylist. No action being taken.')

    # This function sits around 133mb of memory usage at creation date, if we don't cleanup, high activity projects may run into issues.
    del log_entry
    gc.collect()

def check_resource(project_id, firewall_name):
    """
    Checks the firewall for 0.0.0.0/0 and disables the firewall if found.
    """
    logging.info(f'Received firewall create/update log from Pub/Sub in an enabled project. Checking firewall: {firewall_name} for enablement status.')

    # Determine if CFN is running in view-only mode
    try:
        mode = getenv('MODE')
    except:
        logging.error('Mode not found in environment variable.')
    
    # Determine alerting method and create the Notification method class
    try:
        alerting_method = getenv("NOTIFICATION_METHOD")
        notify = Notify(alerting_method)
    except:
        logging.error('Notification method not found in environment variable.')

    # Create compute client to make API calls
    compute_client = create_service()

    # Get firewall information
    firewall_metadata = describe_firewall(compute_client, firewall_name, project_id)

    # Extract info about the firewall to check if it has 0.0.0.0/0 and if it is enabled.
    source_ranges = firewall_metadata['sourceRanges']
    disabled = firewall_metadata['disabled']

    if ('0.0.0.0/0' in source_ranges and not disabled):
        finding_type = "public_firewall_port"

        # Create an active finding
        message = f"Found 0.0.0.0/0 ingress on enabled firewall rule: {firewall_name} in project: {project_id}."
        finding = LockdownFinding(
            finding_type="FIREWALL_GLOBAL_ALLOW",
            message=message,
            resource_id=,
            event_time=
            )

        if mode == "write":
            logging.info(f"Lockdown is in write mode. Disabling firewall rule: {firewall_name}.")
            try:
                # Disables the firewall rule, if successful, set the finding to inactive before notifying.
                disable_firewall(compute_client, firewall_name, project_id)
                finding.set_finding_inactive
            except Exception as error:
                # if we get an error disabling the firewall, still send the finding to the notify endpoint
                logging.error(f"Unable to disable firewall: {firewall_name}. Recieved error: {error}")
                notify.send(finding)
        if mode == "read":
            logging.info('Lockdown is in read-only mode. Taking no action.')
        try:
            notify.send(finding)
        except:
            logging.error(f"Error sending notification for finding: {finding.pubsub_message_contents}  Recieved error: {error}")
    else:
        logging.info(f"The firewall rule: {firewall_name} is not enabled or 0.0.0.0/0 was removed.")

    # More cleanup
    del compute_client

def describe_firewall(compute_client, firewall_name, project_id):
    """
    Gets information about the firewall
    """
    try:
        request = compute_client.firewalls().get(project=project_id, firewall=firewall_name)
        response = request.execute(num_retries=5)
    except:
        logging.error(f'Could not retrieve enablement status for {firewall_name}.')
        raise
    return response

def disable_firewall(compute_client, firewall_name, project_id):
    """
    Disables a firewall rule
    """
    firewall_body = {
    "name": firewall_name,
    "disabled": "true"
    }
    try:
        request = compute_client.firewalls().patch(project=project_id, firewall=firewall_name, body=firewall_body)
        response = request.execute(num_retries=5)
    except:
        logging.error(f'Could not disable firewall: {firewall_name}.')
        raise

def create_service():
    """
    Creates the GCP Compute Service.
    """
    return googleapiclient.discovery.build('compute', 'v1', cache=MemoryCache())

class MemoryCache(Cache):
    """
    File-based cache to resolve GCP Cloud Function noisey log entries.
    """
    _CACHE = {}

    def get(self, url):
        return MemoryCache._CACHE.get(url)

    def set(self, url, content):
        MemoryCache._CACHE[url] = content
