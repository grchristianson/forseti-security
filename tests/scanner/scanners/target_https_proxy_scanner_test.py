# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Target Https Proxy Scanner Test"""

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.scanners import target_https_proxy_scanner
from tests.unittest_utils import get_datafile_path
from google.cloud.forseti.common.gcp_type import target_https_proxy as thp


class TargetHttpsProxy(object):
    """Represents TargetHttpsProxy resource."""

class TargetHttpsProxyScannerTest(ForsetiTestCase):

    def test_target_https_proxy_rules_scanner_no_violations(self):
        rules_local_path = get_datafile_path(__file__,
            'target_https_proxy_test_1.yaml')
        scanner = target_https_proxy_scanner.TargetHttpsProxyScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)

        project_id = "project-1"

        gcp_target_https_proxy_resource_data = [
            {
                "id": "proxy-1",
                "sslPolicy": "policy",
                "name": "proxy-1",
                "description": "description-1",
            },
            {
                "id": "proxy-2",
                "name": "proxy-2",
                "description": "description-2",
            },
        ]
        gcp_target_https_proxy_resource_objs = []
        for gcp_target_https_proxy_resource in gcp_target_https_proxy_resource_data:
            gcp_target_https_proxy_resource_objs.append(
                thp.TargetHttpsProxy.from_dict(
                    project_id, '', gcp_target_https_proxy_resource))

        violations = scanner._find_violations(gcp_target_https_proxy_resource_objs)
        print(violations)
        self.assertEqual(0, len(violations))

    # def test_target_https_proxy_rules_scanner_exempt(self):
    #     rules_local_path = get_datafile_path(__file__,
    #         'target_https_proxy_test_1.yaml')
    #     scanner = target_https_proxy_scanner.TargetHttpsProxyScanner(
    #         {}, {}, mock.MagicMock(), '', '', rules_local_path)
    #
    #     project_id = "project-1"
    #
    #     gcp_target_https_proxy_resource_data = [
    #         {
    #             "id": "proxy-1",
    #             "sslPolicy": "policy-1",
    #             "name": "proxy-1",
    #             "description": "description-1",
    #         },
    #         {
    #             "id": "proxy-2",
    #             "sslPolicy": "policy-2",
    #             "name": "proxy-2",
    #             "description": "description-2",
    #         },
    #     ]
    #     gcp_target_https_proxy_resource_objs = []
    #     for gcp_target_https_proxy_resource in gcp_target_https_proxy_resource_data:
    #         gcp_target_https_proxy_resource_objs.append(
    #             thp.TargetHttpsProxy.from_dict(
    #                 project_id, '', gcp_target_https_proxy_resource))
    #
    #     violations = scanner._find_violations(gcp_target_https_proxy_resource_objs)
    #     print(violations)
    #     self.assertEqual(0, len(violations))

    # def test_target_https_proxy_scanner_no_match(self):
    #     rules_local_path = get_datafile_path(__file__,
    #         'target_https_proxy_test_1.yaml')
    #     scanner = target_https_proxy_scanner.TargetHttpsProxyScanner(
    #         {}, {}, mock.MagicMock(), '', '', rules_local_path)
    #
    #     project_id = "abc-123"
    #
    #     gcp_target_https_proxy_resource_data = [
    #         {
    #             "id": "test_proxy_1",
    #             "sslPolicy": "ssl-1",
    #             "name": "proxy-v1",
    #             "description": "description_1",
    #         },
    #         {
    #             "id": "test_proxy_2",
    #             "sslPolicy": "ssl-2",
    #             "name": "proxy-v2",
    #             "description": "description_2",
    #         },
    #     ]
    #     gcp_target_https_proxy_resource_objs = []
    #     for gcp_target_https_proxy_resource in gcp_target_https_proxy_resource_data:
    #         gcp_target_https_proxy_resource_objs.append(
    #             thp.TargetHttpsProxy.from_dict(
    #                 project_id, '', gcp_target_https_proxy_resource)
    #             )
    #
    #     violations = scanner._find_violations(gcp_target_https_proxy_resource_objs)
    #     self.assertEqual(2, len(violations))
    #
    # def test_target_https_proxy_scanner_proxy_name(self):
    #     rules_local_path = get_datafile_path(__file__,
    #         'target_https_proxy_test_1.yaml')
    #     scanner = target_https_proxy_scanner.TargetHttpsProxyScanner(
    #         {}, {}, mock.MagicMock(), '', '', rules_local_path)
    #
    #     project_id = "abc-123"
    #
    #     gcp_target_https_proxy_resource_data = [
    #         {
    #             "id": "proxy_0",
    #             "sslPolicy": "policy_0",
    #             "name": "proxy_0_name",
    #             "description": "description_0",
    #         },
    #     ]
    #     gcp_target_https_proxy_resource_objs = []
    #     for gcp_target_https_proxy_resource in gcp_target_https_proxy_resource_data:
    #         gcp_target_https_proxy_resource_objs.append(
    #             thp.TargetHttpsProxy.from_dict(
    #                 project_id, '', gcp_target_https_proxy_resource)
    #             )
    #
    #     violations = scanner._find_violations(gcp_target_https_proxy_resource_objs)
    #     self.assertEqual(0, len(violations))


if __name__ == '__main__':
    unittest.main()
