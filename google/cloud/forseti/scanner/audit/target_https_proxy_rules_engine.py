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


class TargetHttpsProxyRulesEngine(bre.BaseRulesEngine):
    """Rules engine for target https proxy"""

    RuleViolation = namedtuple('RuleViolation',
                               ['violation_type', 'rule_index', 'resource_type',
                                'resource_data', 'resource_id', 'full_name',
                                'resource_name', 'self_link', 'url_map',
                                'ssl_certificates', 'quic_override', 'ssl_policy', 'kind'])

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(TargetHttpsProxyRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            snapshot_timestamp=snapshot_timestamp)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build target https proxy rule book from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = TargetHttpsProxyRulesBook(self._load_rule_definitions())

    def find_violations(self, target_https_proxy, force_rebuild=False):
        """Determine whether target proxy violates rules.

        Args:
            target_https_proxy (TargetHttpsProxy): The TargetHttpsProxy
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

        # If your fwd rule matches at least 1 rule in rulebook return None
        # else your fwd rule violates the rulebook and will return a violation
        for rule in resource_rules:
            if rule.find_match(target_https_proxy):
                return self.RuleViolation(
                    violation_type='TARGET_HTTPS_PROXY_VIOLATION',
                    resource_id=target_https_proxy.resource_id,
                    full_name=target_https_proxy.full_name,
                    rule_index=len(resource_rules),
                    resource_name=target_https_proxy.name,
                    resource_type=ResourceType.TARGET_HTTPS_PROXY,
                    resource_data=str(target_https_proxy),
                    self_link=target_https_proxy.self_link,
                    url_map=target_https_proxy.url_map,
                    ssl_certificates=target_https_proxy.ssl_certificates,
                    quic_override=target_https_proxy.quic_override,
                    ssl_policy=target_https_proxy.ssl_policy,
                    kind=target_https_proxy.kind)
        return None



    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (dict): rule from file to be added to book
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class TargetHttpsProxyRulesBook(bre.BaseRuleBook):
    """The RuleBook for target https proxy resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitions
        """
        super(TargetHttpsProxyRulesBook, self).__init__()
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
        proxy_name = rule_def.get('proxy_name')
        ssl_policy = rule_def.get('ssl_policy')
        if ((proxy_name is None) or (ssl_policy is None)):
            raise audit_errors.InvalidRulesSchemaError(
                'Faulty rule {}'.format(rule_def.get('name')))
        rule_def_resource = {'proxy_name': proxy_name,
                             'ssl_policy': ssl_policy,
                             'full_name': ''}

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

    def find_match(self, target_https_proxy):
        """Find if the passed in target https proxy violates any in the rule book

        Args:
            target_https_proxy (TargetHttpsProxy): target https proxy resource

        Returns:
            bool: true if the target https proxy violated at least 1 rule in the
                rulebook
        """
        if (self.rules['proxy_name'] == '*') or (self.rules['proxy_name'] == target_https_proxy.name):
            return target_https_proxy.ssl_policy != self.rules['ssl_policy']
        return False
