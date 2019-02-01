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

"""A Compute Target Https Proxy.

See: https://cloud.google.com/compute/docs/reference/latest/targetHttpsProxies
"""

import json


# pylint: disable=too-many-arguments
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-locals
class TargetHttpsProxy(object):
    """Represents TargetHttpsProxy resource."""

    def __init__(self, project_id, resource_id, full_name, creation_timestamp,
                 name, description, self_link, url_map, ssl_certificates,
                 quic_override, ssl_policy, kind, raw_json):
        """Target Https Proxy resource.

        Args:
            project_id (str): The project containing the Target Https Proxy .
            resource_id (str): The id of the Target Https Proxy .
            full_name (str): The full resource name and ancestory.
            creation_timestamp (str): Timestampe when the Target Https Proxy was
                created.
            name (str): The name of the Target Https Proxy.
            description (str): Description of the Target Https Proxy.
            self_link (str): self link
            url_map (str): url map
            ssl_certificates (list): SSL Certificates
            quic_override (str): quic override
            ssl_policy (str): ssl_policy
            kind (str): kind
            raw_json (str): The raw json string for the forwarding rule.
        """
        self.project_id = project_id
        self.resource_id = resource_id
        self.full_name = full_name
        self.creation_timestamp = creation_timestamp
        self.name = name
        self.description = description
        self.self_link = self_link
        self.url_map = url_map
        self.ssl_certificates = ssl_certificates
        self.quic_override = quic_override
        self.ssl_policy = ssl_policy
        self.kind = kind
        self._json = raw_json

    @classmethod
    def from_dict(cls, project_id, full_name, target_https_proxy):
        """Returns a new Target Https Proxy object from dict.

        Args:
            project_id (str): The project id.
            full_name (str): The full resource name and ancestory.
            target_https_proxy (dict): The Target Https Proxy rule.

        Returns:
            TargetHttpsProxy: A new TargetHttpsProxy object.
        """
        return cls(
            project_id=project_id,
            resource_id=target_https_proxy.get('id'),
            full_name=full_name,
            creation_timestamp=target_https_proxy.get('creationTimestamp', ''),
            name=target_https_proxy.get('name', ''),
            description=target_https_proxy.get('description', ''),
            self_link=target_https_proxy.get('selfLink,' ''),
            url_map=target_https_proxy.get('urlMap',''),
            ssl_certificates=target_https_proxy.get('sslCertificates',''),
            quic_override=target_https_proxy.get('quicOverride',''),
            ssl_policy=target_https_proxy.get('sslPolicy',''),
            kind=target_https_proxy.get('kind',''),
            raw_json=json.dumps(target_https_proxy, sort_keys=True)
        )

    @staticmethod
    def from_json(project_id, full_name, target_https_proxy_data):
        """Returns a new TargetHttpsProxy object from json data.

        Args:
            project_id (str): the project id.
            full_name (str): The full resource name and ancestory.
            target_https_proxy_data (str): The json data representing
                the proxy.

        Returns:
           TargetHttpsProxy: A new TargetHttpsProxy object.
        """
        target_https_proxy = json.loads(target_https_proxy_data)
        return TargetHttpsProxy.from_dict(project_id, full_name, target_https_proxy)

    def __repr__(self):
        """String representation.
        Returns:
            str: Json string.
        """
        return self._json

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: The hash of the class properties.
        """
        return hash(self._json)
