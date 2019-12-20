import unittest
from unittest import mock
import json
import responses
from .util import create_task
from cumulusci.tasks.salesforce.ActivateFlowProcesses import ActivateFlowProcesses

task_options = {
    "description": "Activates Flows identified by a given list of Developer Names",
    "developer_names": ["Auto_Populate_Date_And_Name_On_Program_Engagement", "ape"],
    "required": True,
}

task_no_developer_options = {
    "description": "Activates Flows identified by a given list of Developer Names",
    "developer_names": [],
    "required": True,
}


class TestActivateFlowProcesses(unittest.TestCase):
    @responses.activate
    def test_activate_flow_processes(self):
        cc_task = create_task(ActivateFlowProcesses, task_options)
        record_id = "3001F0000009GFwQAM"
        activate_url = "{}/services/data/v43.0/tooling/sobjects/FlowDefinition/{}".format(
            cc_task.org_config.instance_url, record_id
        )
        responses.add(
            method="GET",
            url="https://test.salesforce.com/services/data/v43.0/tooling/query/?q=SELECT+Id%2C+ActiveVersion.VersionNumber%2C+LatestVersion.VersionNumber%2C+DeveloperName+FROM+FlowDefinition+WHERE+DeveloperName+IN+%28%27Auto_Populate_Date_And_Name_On_Program_Engagement%27%2C%27ape%27%29",
            body=json.dumps(
                {
                    "records": [
                        {
                            "Id": record_id,
                            "DeveloperName": "Auto_Populate_Date_And_Name_On_Program_Engagement",
                            "LatestVersion": {"VersionNumber": 1},
                        }
                    ]
                }
            ),
            status=200,
        )
        data = {"Metadata": {"activeVersionNumber": 1}}
        responses.add(method=responses.PATCH, url=activate_url, status=204, json=data)

        cc_task()
        self.assertEqual(2, len(responses.calls))


class TestActivateMultipleFlowProcesses(unittest.TestCase):
    @responses.activate
    def test_activate_flow_processes(self):
        cc_task = create_task(ActivateFlowProcesses, task_options)
        record_id = "3001F0000009GFwQAM"
        activate_url = "{}/services/data/v43.0/tooling/sobjects/FlowDefinition/{}".format(
            cc_task.org_config.instance_url, record_id
        )
        responses.add(
            method="GET",
            url="https://test.salesforce.com/services/data/v43.0/tooling/query/?q=SELECT+Id%2C+ActiveVersion.VersionNumber%2C+LatestVersion.VersionNumber%2C+DeveloperName+FROM+FlowDefinition+WHERE+DeveloperName+IN+%28%27Auto_Populate_Date_And_Name_On_Program_Engagement%27%2C%27ape%27%29",
            body=json.dumps(
                {
                    "records": [
                        {
                            "Id": record_id,
                            "DeveloperName": "Auto_Populate_Date_And_Name_On_Program_Engagement",
                            "LatestVersion": {"VersionNumber": 1},
                        },
                        {
                            "Id": record_id,
                            "DeveloperName": "ape",
                            "LatestVersion": {"VersionNumber": 1},
                        },
                    ]
                }
            ),
            status=200,
        )
        data = {"Metadata": {"activeVersionNumber": 1}}
        responses.add(method=responses.PATCH, url=activate_url, status=204, json=data)
        responses.add(method=responses.PATCH, url=activate_url, status=204, json=data)
        cc_task()
        self.assertEqual(3, len(responses.calls))


class TestNoDeveloperFlowProcesses(unittest.TestCase):
    @responses.activate
    def test_activate_flow_processes(self):
        result = mock.Mock()
        final = result.create_task(ActivateFlowProcesses, task_no_developer_options)
        self.assertEqual(0, len(responses.calls))
        final.assert_not_called()
