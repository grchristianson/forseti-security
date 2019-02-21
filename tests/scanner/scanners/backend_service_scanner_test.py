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
from google.cloud.forseti.scanner.scanners import backend_service_scanner
from tests.unittest_utils import get_datafile_path
from google.cloud.forseti.common.gcp_type import backend_service as bs


class BackendService(object):
    """Represents BackendService resource."""

class BackendServiceScannerTest(ForsetiTestCase):

    def test_backend_service_rules_scanner_all_match(self):
        rules_local_path = get_datafile_path(__file__,
            'backend_service_test_1.yaml')
        scanner = backend_service_scanner.BackendServiceScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)

        project_id = "abc-123"

        gcp_backend_service_resource_data = [
            {
                "id": "test_backend_service_0",
                "securityPolicy": "policy0",
                "name": "test_backend_service_0_name",
                "description": "description_0",
            },
            {
                "id": "test_backend_service_1",
                "securityPolicy": "policy0",
                "name": "test_backend_service_1_name",
                "description": "description_1",
            },
        ]
        gcp_backend_service_resource_objs = []
        for gcp_backend_service_resource in gcp_backend_service_resource_data:
            gcp_backend_service_resource_objs.append(
                bs.BackendService.from_dict(
                    '', gcp_backend_service_resource, project_id))

        print(gcp_backend_service_resource_objs)

        violations = scanner._find_violations(gcp_backend_service_resource_objs)
        self.assertEqual(0, len(violations))

    def test_backend_service_scanner_no_match(self):
        rules_local_path = get_datafile_path(__file__,
            'backend_service_test_1.yaml')
        scanner = backend_service_scanner.BackendServiceScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)

        project_id = "abc-123"

        gcp_backend_service_resource_data = [
            {
                "id": "test_backend_service_0",
                "securityPolicy": "wrong_policy",
                "name": "test_backend_service_0_name",
                "description": "description_0",
            },
            {
                "id": "test_backend_service_1",
                "securityPolicy": "wrong_policy",
                "name": "test_backend_service_1_name",
                "description": "description_1",
            },
        ]

        gcp_backend_service_resource_objs = []
        for gcp_backend_service_resource in gcp_backend_service_resource_data:
            gcp_backend_service_resource_objs.append(
                bs.BackendService.from_dict(
                    '', gcp_backend_service_resource, project_id)
                )

        violations = scanner._find_violations(gcp_backend_service_resource_objs)
        self.assertEqual(2, len(violations))


if __name__ == '__main__':
    unittest.main()
