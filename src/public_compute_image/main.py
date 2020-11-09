import base64
import json
import logging

from os import getenv
from google.cloud import logging as glogging
from google.cloud import pubsub_v1
from googleapiclient.discovery_cache.base import Cache
import googleapiclient.discovery


def pubsub_trigger(data, context):
    """
    Used with Pub/Sub trigger method to evaluate the compute image IAM policy for public members.
    """

    # Determine if CFN is running in view-only mode
    try:
        mode = getenv('MODE')
    except:
        logging.error('Mode not found in environment variable.')

    # Create compute client to make API calls
    compute_client = create_service()

    # Integrates cloud logging handler to python logging
    create_logger()

    logging.info('Received compute image IAM update log from Pub/Sub. Checking for public members.')

    # Converting log to json
    data_buffer = base64.b64decode(data['data'])
    log_entry = json.loads(data_buffer)

    # Get image ID from log event
    image_id = log_entry['protoPayload']['resourceName']

    # Create the image resource ID
    # Split the image_id into a list of strings
    image_list = image_id.split('/')
    # Set our list of strings to remove
    remove_strings = ["projects", "global", "images"]
    # Remove all strings in list to create a list project_id and image_id
    project_image_id = [i for i in image_list if i not in remove_strings]
    # Create the project_id and image_id variables
    project_id = project_image_id[0]
    image_id = project_image_id[1]

    # Get the compute image IAM policy
    policy = get_iam_policy(compute_client, image_id, project_id)

    # Generate a new policy without public members
    new_policy = eval_iam_policy(policy, image_id, project_id)

    if new_policy:
        # Set our pub/sub message
        message = f"Lockdown is in mode: {mode}. Found public members on compute image: {image_id}."
        # Publish message to Pub/Sub
        logging.info('Publishing message to Pub/Sub.')
        publish_message(project_id, message)
        if mode == "write":
            logging.info(f'Lockdown is in write mode. Updating compute image: {image_id} with new IAM policy."')
            # Updates compute image with private IAM policy
            set_iam_policy(new_policy, compute_client, image_id, project_id)
        if mode == "read":
            logging.info('Lockdown is in read-only mode. Taking no action.')
    else:
        logging.info(f"The compute image: {image_id} is not public facing.")

def get_iam_policy(compute_client, image_id, project_id):
    """
    Gets the compute image IAM policy.
    """

    try:
        policy = compute_client.images().getIamPolicy(project=project_id, resource=image_id).execute()
    except:
        logging.error(f"Could not get compute image IAM policy on image {compute_client}.")
        raise

    return policy

def eval_iam_policy(policy, image_id, project_id):
    """
    Check for public IAM members in compute image policy.
    """

    # Create the public users list to reference when creating new members.
    public_users = ["allAuthenticatedUsers", "allUsers"]

    # Create our new bindings
    bindings = []

    # Get the IAM bindings
    for binding in policy["bindings"]:
        # Creates our members list for each IAM binding
        members = binding.get("members")
        # Check to see if there is an IAM policy directly attached to the compute image
        if members:
            # Reference our public users list and remove from members
            new_members = [i for i in members if i not in public_users]
            # Check to see if the members list is different
            # If the members lists are not the same, a public member was found
            if new_members != members:
                logging.info(f"Public IAM member found on compute image: {image_id} in project: {project_id}..")
                # Create a new binding using the same role and updated members list
                new_binding = {
                    "role": binding["role"],
                    "members": sorted(new_members)
                }
                # Use the same condition on mew IAM binding
                condition = binding.get("condition")
                if condition:
                    new_binding["condition"] = condition
                # Add our new binding to the bindings variable for the new policy
                bindings.append(new_binding)
                public = "true"
            else:
                logging.info(f'Binding: {binding} does not contain a public IAM member on image: {image_id} in project: {project_id}.')
                bindings.append(binding)
        else:
            logging.info(f'No IAM bindings found on compute image: {image_id}.')
    # Set the new bindings entry using the updated bindings variable
    policy["bindings"] = bindings

    if "public" in locals():
        return policy
    else:
        logging.info(f"The IAM policy on compute image: {image_id} is private.")


def set_iam_policy(new_policy, compute_client, image_id, project_id):
    """
    Set the new compute image private IAM policy.
    """

    try:
        compute_client.images().setIamPolicy(project=project_id, resource=image_id, body=new_policy).execute()
        logging.info(f"Updated IAM policy on compute image: {image_id} in project: {project_id}.")
    except:
        logging.error(f"Could not update IAM policy on compute image: {image_id} in project: {project_id}.")
        raise

def publish_message(project_id, message):
    """
    Publishes message to Pub/Sub topic for integration into alerting system.
    """

    # Create Pub/Sub Client
    pub_client = pubsub_v1.PublisherClient()

    try:
        topic_id = getenv('TOPIC_ID')
    except:
        logging.error('Topic ID not found in environment variable.')

    # Create topic object
    topic = pub_client.topic_path(project_id, topic_id)

    # Pub/Sub messages must be a bytestring
    data = message.encode("utf-8")

    try:
        pub_client.publish(topic, data)
        logging.info(f'Published message to {topic}')
    except:
        logging.error(f'Could not publish message to {topic_id}')
        raise

def create_service():
    """
    Creates the GCP Compute Service.
    """
    return googleapiclient.discovery.build('compute', 'v1', cache=MemoryCache())

def create_logger():
    """
    Integrates the Cloud Logging handler with the python logging module.
    """
    # Instantiates a cloud logging client
    client = glogging.Client()

    # Retrieves a Cloud Logging handler based on the environment
    # you're running in and integrates the handler with the
    # Python logging module
    client.get_default_handler()
    client.setup_logging()

class MemoryCache(Cache):
    """
    File-based cache to resolve GCP Cloud Function noisey log entries.
    """
    _CACHE = {}

    def get(self, url):
        return MemoryCache._CACHE.get(url)

    def set(self, url, content):
        MemoryCache._CACHE[url] = content