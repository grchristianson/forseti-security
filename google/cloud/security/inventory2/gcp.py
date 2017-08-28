# Copyright 2017 Google Inc.
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

""" GCP API client fassade. """

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc
# pylint: disable=missing-param-doc,invalid-name,too-many-instance-attributes
# pylint: disable=too-many-public-methods,arguments-differ

from google.cloud.security.common.gcp_api2 import admin_directory
from google.cloud.security.common.gcp_api2 import appengine
from google.cloud.security.common.gcp_api2 import bigquery
from google.cloud.security.common.gcp_api2 import cloud_resource_manager
from google.cloud.security.common.gcp_api2 import cloudsql
from google.cloud.security.common.gcp_api2 import compute
from google.cloud.security.common.gcp_api2 import iam
from google.cloud.security.common.gcp_api2 import storage


class ApiClient(object):
    """The gcp api client interface"""
    def fetch_organization(self, orgid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_projects(self, orgid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_folders(self, orgid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_buckets(self, projectid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_objects(self, bucket_id):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def get_organization_iam_policy(self, orgid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def get_project_iam_policy(self, projectid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()


class ApiClientImpl(ApiClient):
    """The gcp api client Implementation"""
    def __init__(self, config):
        self.ad = admin_directory.AdminDirectoryClient(config)
        self.appengine = appengine.AppEngineClient(config)
        self.bigquery = bigquery.BigQueryClient(config)
        self.crm = cloud_resource_manager.CloudResourceManagerClient(config)
        self.cloudsql = cloudsql.CloudsqlClient(config)
        self.compute = compute.ComputeClient(config)
        self.iam = iam.IAMClient(config)
        self.storage = storage.StorageClient(config)

        self.cached_folders = None
        self.cached_projects = None

    def iter_users(self, gsuite_id):
        """Gsuite user Iterator from gcp API call

        Yields:
            dict: Generator of user
        """
        for user in self.ad.get_users(gsuite_id):
            yield user

    def iter_groups(self, gsuite_id):
        """Gsuite group Iterator from gcp API call

        Yields:
            dict: Generator of groups
        """
        result = self.ad.get_groups(gsuite_id)
        for group in result:
            yield group

    def iter_group_members(self, group_key):
        """Gsuite group_memeber Iterator from gcp API call

        Yields:
            dict: Generator of group_member
        """
        for member in self.ad.get_group_members(group_key):
            yield member

    def fetch_organization(self, orgid):
        """Organization data from gcp API call

        Returns:
            dict: Generator of organization
        """
        return self.crm.get_organization(orgid)

    def iter_projects(self, parent_type, parent_id):
        """Project Iterator from gcp API call

        Yields:
            dict: Generator of projects
        """
        if self.cached_projects is None:
            self.cached_projects = []
            for page in self.crm.get_projects(parent_id):
                for project in page['projects']:
                    self.cached_projects.append(project)

        for project in self.cached_projects:
            parent_info = project['parent']
            if parent_info['type'] == parent_type and \
               parent_info['id'] == parent_id:
                yield project

    def iter_folders(self, parent_id):
        """Folder Iterator from gcp API call

        Yields:
            dict: Generator of folders
        """
        if self.cached_folders is None:
            self.cached_folders = []
            for response in self.crm.get_folders(parent_id):
                if 'folders' in response:
                    for folder in response['folders']:
                        self.cached_folders.append(folder)

        for folder in self.cached_folders:
            if folder['parent'] == parent_id:
                yield folder

    def iter_buckets(self, projectid):
        """Bucket Iterator from gcp API call

        Yields:
            dict: Generator of buckets
        """
        response = self.storage.get_buckets(projectid)
        if 'items' not in response:
            return

        for bucket in response['items']:
            yield bucket

    def iter_objects(self, bucket_id):
        """Object Iterator from gcp API call

        Yields:
            dict: Generator of objects
        """
        for object_ in self.storage.get_objects(bucket_name=bucket_id):
            yield object_

    def iter_datasets(self, projectid):
        """Dataset Iterator from gcp API call

        Yields:
            dict: Generator of datasets
        """
        response = self.bigquery.get_datasets_for_projectid(projectid)
        for dataset in response:
            yield dataset

    def iter_appengineapps(self, projectid):
        """ Appengine Iterator from gcp API call

        Yields:
            dict: Generator of appengine
        """
        response = self.appengine.get_app(projectid)
        if not response:
            return
        yield response

    def iter_cloudsqlinstances(self, projectid):
        """Cloudsqlinstance Iterator from gcp API call

        Yields:
            dict: Generator of cloudsql instance
        """
        result = self.cloudsql.get_instances(projectid)
        if 'items' not in result:
            return
        for item in result['items']:
            yield item

    def iter_computeinstances(self, projectid):
        """Compute Engine Instance Iterator from gcp API call

        Yields:
            dict: Generator of Compute Engine Instance
        """
        result = self.compute.get_instances(projectid)
        for instance in result:
            yield instance

    def iter_computefirewalls(self, projectid):
        """Compute Engine Firewall Iterator from gcp API call

        Yields:
            dict: Generator of Compute Engine Firewall
        """
        result = self.compute.get_firewall_rules(projectid)
        for rule in result:
            yield rule

    def iter_computeinstancegroups(self, projectid):
        """Compute Engine group Iterator from gcp API call

        Yields:
            dict: Generator of Compute Instance group
        """
        result = self.compute.get_instance_groups(projectid)
        for instancegroup in result:
            yield instancegroup

    def iter_backendservices(self, projectid):
        """Backend service Iterator from gcp API call

        Yields:
            dict: Generator of backend service
        """
        result = self.compute.get_backend_services(projectid)
        for backendservice in result:
            yield backendservice

    def iter_serviceaccounts(self, projectid):
        """Service Account Iterator in a project from gcp API call

        Yields:
            dict: Generator of service account
        """
        for serviceaccount in self.iam.get_serviceaccounts(projectid):
            yield serviceaccount

    def iter_project_roles(self, projectid):
        """Project role Iterator in a project from gcp API call

        Yields:
            dict: Generator of project roles
        """
        for role in self.iam.get_project_roles(projectid):
            yield role

    def iter_organization_roles(self, orgid):
        """Organization role Iterator from gcp API call

        Yields:
            dict: Generator of organization role
        """
        for role in self.iam.get_organization_roles(orgid):
            yield role

    def iter_curated_roles(self, orgid):
        """Curated role Iterator in an organization from gcp API call

        Yields:
            dict: Generator of curated roles
        """
        for role in self.iam.get_curated_roles(orgid):
            yield role

    def get_folder_iam_policy(self, folderid):
        """Folder IAM policy in a folder from gcp API call

        Returns:
            dict: Folder IAM policy
        """
        return self.crm.get_folder_iam_policies(folderid)

    def get_organization_iam_policy(self, orgid):
        """Organization IAM policy from gcp API call

        Returns:
            dict: Organization IAM policy
        """
        return self.crm.get_org_iam_policies(orgid, orgid)

    def get_project_iam_policy(self, projectid):
        """Project IAM policy from gcp API call

        Returns:
            dict: Project IAM Policy
        """
        return self.crm.get_project_iam_policies(projectid, projectid)

    def get_bucket_gcs_policy(self, bucketid):
        """Bucket GCS policy from gcp API call

        Returns:
            dict: Bucket GCS policy
        """
        result = self.storage.get_bucket_acls(bucketid)
        if 'items' not in result:
            return []
        return result['items']

    def get_bucket_iam_policy(self, bucketid):
        """Bucket IAM policy Iterator from gcp API call

        Returns:
            dict: Bucket IAM policy
        """
        return self.storage.get_bucket_iam_policy(bucketid)

    def get_object_gcs_policy(self, bucket_name, object_name):
        """Object GCS policy for an object from gcp API call

        Returns:
            dict: Object GCS policy
        """
        result = self.storage.get_object_acls(bucket_name, object_name)
        if 'items' not in result:
            return []
        return result['items']

    def get_object_iam_policy(self, bucket_name, object_name):
        """Object IAM policy Iterator for an object from gcp API call

        Returns:
            dict: Object IAM policy
        """
        return self.storage.get_object_iam_policy(bucket_name, object_name)

    def get_dataset_dataset_policy(self, projectid, datasetid):
        """Dataset policy Iterator for a dataset from gcp API call

        Returns:
            dict: Dataset Policy
        """
        return self.bigquery.get_dataset_access(projectid, datasetid)