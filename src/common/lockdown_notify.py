from google.cloud import pubsub_v1
from google.cloud import securitycenter
from google.cloud.securitycenter_v1 import CreateFindingRequest, Finding, SourcePropertiesEntry
import datetime
import json
from os import getenv

class LockdownFinding:
    """
    A finding object specific to Project Lockdown that is used 
    in the Notify class to send to the various notification options

    Usage:

    notification = Notify("scc")
    finding = LockdownFinding("Test_Finding_type", "ACTIVE", "hello this is a message", "resource", "noon")
    notification.send(finding)

    """
    def __init__(self, finding_type, state, message, resource_id, event_time):
        self.finding_type = finding_type
        self.state = state
        self.message = message
        self.resource_id = resource_id
        self.event_time = event_time  

    @property
    def finding_type():
        return self.finding_type

    @property
    def state():
        return self.state

    @property
    def message():
        return self.message

    @property
    def resource_id():
        return self.resource_id

    @property
    def event_time():
        return self.event_time

    @property
    def pubsub_message_contents():
        return {
            "finding": self.finding_type,
            "mode": self.mode,
            "resourceId": self.resource_id,
            "message": self.message
        }

class Notify:
    """
    Class for Project Lockdown to send findings to Pub/Sub, Security Command Center.
    """
    def __init__(self, notification_method):
        self.notification_method = notification_method

        if self.notification_method == "scc":
            # Create SCC client with Project Lockdown source
            self.source_name = getenv('SOURCE_NAME')
            self.scc_client = securitycenter.SecurityCenterClient()
            self.source = client.get_source(request={"name": source_name})

        if self.notification_method == "pubsub":
            # Create Pub/Sub Client
            self.pub_client = pubsub_v1.PublisherClient()
            self.topic_id = getenv('TOPIC_ID')


    def pubsub(self, lockdown_finding):
        """
        Publishes message to Pub/Sub topic for integration into alerting system.
        """

        # Get the dictionary of all results from the lockdown object
        message_json = json.dumps(lockdown_finding.pubsub_message)

        # Create topic object
        topic = self.pub_client.topic_path(project_id, topic_id)

        # Pub/Sub messages must be a bytestring
        data = message_json.encode("utf-8")
        
        # Publish message
        self.pub_client.publish(topic, data)


    def scc(self, lockdown_finding):
        """
        Creates a new finding.
        https://github.com/googleapis/python-securitycenter/blob/master/samples/snippets/snippets_findings.py

        Args:
            lockdown_finding: a LockdownFinding object
        """

        # Create a finding object
        finding = Finding(
            state=Finding.State.ACTIVE,
            resource_name=lockdown_finding.resource_id,
            category=lockdown_finding.finding_type,
            event_time=lockdown_finding.event_time,
            source_properties={"summary": lockdown_finding.message},
        )

        # Request object to send to SCC
        request = CreateFindingRequest(
            parent=self.source,
            finding_id=finding_id,
            finding=finding,
        )

        # Call The API.
        created_finding = self.scc_client.create_finding(
            request=request
        )

    def send(self, lockdown_finding):
        """
        Sends the message to the designated endpoints.
        """
        if self.notification_method == "scc":
            scc(lockdown_finding)

        if self.notification_method == "pubsub":
            pubsub(lockdown_finding)
