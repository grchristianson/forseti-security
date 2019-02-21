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

"""Rules engine for target https proxy"""
from collections import namedtuple

from google.cloud.forseti.common.gcp_type.resource import ResourceType
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)


class BackendServiceRulesEngine(bre.BaseRulesEngine):
    """Rules engine for backend service"""

    RuleViolation = namedtuple('RuleViolation',
                               ['violation_type', 'rule_index', 'resource_type',
                                'resource_data', 'resource_id', 'full_name',
                                'resource_name',  'affinity_cookie_ttl_sec',
                                'backends', 'cdn_policy', 'connection_draining',
                                'creation_timestamp', 'description', 'enable_cdn',
                                'health_checks', 'iap', 'load_balancing_scheme',
                                'port', 'port_name', 'project_id', 'protocol',
                                'region', 'security_policy', 'session_affinity', 'timeout_sec'])

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(BackendServiceRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            snapshot_timestamp=snapshot_timestamp)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build backend service rule book from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = BackendServiceRulesBook(self._load_rule_definitions())

    def find_violations(self, backend_service, force_rebuild=False):
        """Determine whether backend service violates rules.

        Args:
            backend service (BackendService): The BackendService
                to be compared to rules
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
            RuleViolation: A rule violation tuple with all data about the
            proxy that flagged violation
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        if not resource_rules:
            return None

        for rule in resource_rules:
            if rule.find_match(backend_service):
                return self.RuleViolation(
                    violation_type='BACKEND_SERVICE_VIOLATION',
                    resource_id=backend_service.resource_id,
                    full_name=backend_service.full_name,
                    rule_index=len(resource_rules),
                    resource_name=backend_service.name,
                    resource_type=ResourceType.BACKEND_SERVICE,
                    resource_data=str(backend_service),
                    affinity_cookie_ttl_sec=backend_service.affinity_cookie_ttl_sec,
                    backends=backend_service.backends,
                    cdn_policy=backend_service.cdn_policy,
                    connection_draining=backend_service.connection_draining,
                    creation_timestamp=backend_service.creation_timestamp,
                    description=backend_service.description,
                    enable_cdn=backend_service.enable_cdn,
                    health_checks=backend_service.health_checks,
                    iap=backend_service.iap,
                    load_balancing_scheme=backend_service.load_balancing_scheme,
                    port=backend_service.port,
                    port_name=backend_service.port_name,
                    project_id=backend_service.project_id,
                    protocol=backend_service.protocol,
                    region=backend_service.region,
                    session_affinity=backend_service.session_affinity,
                    security_policy=backend_service.security_policy,
                    timeout_sec=backend_service.timeout_sec)
        return None



    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (dict): rule from file to be added to book
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class BackendServiceRulesBook(bre.BaseRuleBook):
    """The RuleBook for backend service resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitions
        """
        super(BackendServiceRulesBook, self).__init__()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book

        Args:
            rule_defs (dict): list of rules and their index number
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.

        Raises:
            InvalidRulesSchemaError: if rule has format error
        """
        backend_service_name = rule_def.get('backend_service_name')
        security_policy = rule_def.get('security_policy')
        if ((backend_service_name is None) or (security_policy is None)):
            raise audit_errors.InvalidRulesSchemaError(
                'Faulty rule {}'.format(rule_def.get('name')))
        rule_def_resource = {'backend_service_name': backend_service_name,
                             'security_policy': security_policy}

        rule = Rule(rule_name=rule_def.get('name'),
                    rule_index=rule_index,
                    rules=rule_def_resource)

        resource_rules = self.resource_rules_map.get(rule_index)
        if not resource_rules:
            self.resource_rules_map[rule_index] = rule

    def get_resource_rules(self):
        """Get all the resource_rules as a list from the resource_rules_map

        Returns:
            list: A list of ResourceRules.
        """
        return list(self.resource_rules_map.values())


class Rule(object):
    """Rule properties from the rule definition file.
    Also finds violations.
    """

    def __init__(self, rule_name, rule_index, rules):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the rule definitions
            rules (dict): The rules from the file
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules

    def find_match(self, backend_service):
        """Find if the passed in backend service violates any in the rule book

        Args:
            backend_service (BackendService): backend service resource

        Returns:
            bool: true if the backend service violated at least 1 rule in the
                rulebook
        """

        if self.rules['backend_service_name'] == backend_service.name:
            return backend_service.security_policy != self.rules['security_policy']
        return False
