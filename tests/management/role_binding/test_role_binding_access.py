#
# Copyright 2025 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Tests for role binding access permissions using Inventory API."""

from importlib import reload
from unittest.mock import MagicMock, Mock, patch

import requests
from django.test import TransactionTestCase
from django.test.utils import override_settings
from django.urls import clear_url_caches, reverse
from kessel.inventory.v1beta2 import allowed_pb2
from rest_framework import status
from rest_framework.test import APIClient

from management.models import Workspace
from management.permissions.role_binding_access import (
    RoleBindingKesselAccessPermission,
    RoleBindingSystemUserAccessPermission,
)
from rbac import urls
from tests.identity_request import BaseIdentityRequest


class TransactionIdentityRequest(BaseIdentityRequest, TransactionTestCase):
    """Identity request test base class that uses TransactionTestCase."""

    pass


class RoleBindingAccessTestMixin:
    """Mixin providing common setup for role binding access tests."""

    def setUp(self):
        """Set up the role binding access tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.tenant.save()

        self.client = APIClient()

        # Create workspace hierarchy
        self.root_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.ROOT,
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
        )
        self.default_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.DEFAULT,
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            parent=self.root_workspace,
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            description="Test workspace description",
            tenant=self.tenant,
            type=Workspace.Types.STANDARD,
            parent=self.default_workspace,
        )

    def tearDown(self):
        """Tear down test data."""
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.STANDARD).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.DEFAULT).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.ROOT).delete()
        super().tearDown()

    def _get_list_url(self):
        """Get the list URL."""
        return reverse("v2_management:role-bindings-list")

    def _get_by_subject_url(self):
        """Get the by-subject URL."""
        return reverse("v2_management:role-bindings-by-subject")

    def _setup_kessel_mock(self, mock_inventory_client, allowed=allowed_pb2.Allowed.ALLOWED_TRUE):
        """Set up the Kessel Inventory mock with the specified allowed status."""
        mock_stub = MagicMock()
        mock_response = MagicMock()
        mock_response.allowed = allowed
        mock_stub.CheckForUpdate.return_value = mock_response
        mock_inventory_client.return_value.__enter__.return_value = mock_stub
        return mock_stub, mock_response


# ==========================================================================
# RoleBindingSystemUserAccessPermission (unchanged logic)
# ==========================================================================


@override_settings(V2_APIS_ENABLED=True)
class RoleBindingSystemUserPermissionTests(RoleBindingAccessTestMixin, TransactionIdentityRequest):
    """Unit tests for RoleBindingSystemUserAccessPermission."""

    def test_system_user_admin_passes_through(self):
        """Test that system user with admin=True passes through."""
        permission = RoleBindingSystemUserAccessPermission()
        mock_request = Mock()
        mock_request.user.system = True
        mock_request.user.admin = True
        self.assertTrue(permission.has_permission(mock_request, Mock()))

    def test_system_user_non_admin_denied(self):
        """Test that system user without admin=True is denied."""
        permission = RoleBindingSystemUserAccessPermission()
        mock_request = Mock()
        mock_request.user.system = True
        mock_request.user.admin = False
        self.assertFalse(permission.has_permission(mock_request, Mock()))

    def test_regular_admin_passes_through(self):
        """Test that regular admin user passes through."""
        permission = RoleBindingSystemUserAccessPermission()
        mock_request = Mock()
        mock_request.user.system = False
        mock_request.user.admin = True
        self.assertTrue(permission.has_permission(mock_request, Mock()))

    def test_non_admin_non_system_passes_through(self):
        """Test that non-admin, non-system user passes through."""
        permission = RoleBindingSystemUserAccessPermission()
        mock_request = Mock()
        mock_request.user.system = False
        mock_request.user.admin = False
        self.assertTrue(permission.has_permission(mock_request, Mock()))

    def test_handles_user_without_admin_attribute(self):
        """Test that permission handles user without admin attribute safely."""
        permission = RoleBindingSystemUserAccessPermission()
        mock_request = Mock(spec=[])
        mock_request.user = Mock(spec=[])
        self.assertTrue(permission.has_permission(mock_request, Mock()))

    def test_handles_user_without_system_attribute(self):
        """Test that permission handles user without system attribute safely."""
        permission = RoleBindingSystemUserAccessPermission()
        mock_request = Mock()
        mock_request.user = Mock(spec=["admin"])
        mock_request.user.admin = False
        self.assertTrue(permission.has_permission(mock_request, Mock()))


# ==========================================================================
# RoleBindingKesselAccessPermission — action-specific relation tests
# ==========================================================================

CHECKER_PATCH = "management.permissions.role_binding_access.WorkspaceInventoryAccessChecker"
PRINCIPAL_PATCH = "management.permissions.role_binding_access.get_kessel_principal_id"


def _mock_request(query_params=None, data=None):
    """Build a mock request with the given query params and body data."""
    mock = Mock()
    mock.query_params = query_params or {}
    mock.data = data or {}
    return mock


def _mock_view(action, method="GET"):
    """Build a mock view with the given action."""
    view = Mock()
    view.action = action
    return view


@override_settings(V2_APIS_ENABLED=True)
class RoleBindingKesselPermissionRelationTests(RoleBindingAccessTestMixin, TransactionIdentityRequest):
    """Tests that the correct relation(s) are checked for each action."""

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_list_checks_view_relation(self, mock_checker_class, _mock_principal):
        """list action should check VIEW_RELATION."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = True
        mock_checker_class.return_value = mock_checker

        request = _mock_request(query_params={"resource_id": str(self.workspace.id), "resource_type": "workspace"})
        view = _mock_view("list")

        self.assertTrue(permission.has_permission(request, view))
        mock_checker.check_resource_access.assert_called_once()
        call_kwargs = mock_checker.check_resource_access.call_args[1]
        self.assertEqual(call_kwargs["relation"], "rbac_workspaces_role_binding_view")

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_by_subject_get_checks_view_relation(self, mock_checker_class, _mock_principal):
        """by_subject GET should check VIEW_RELATION."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = True
        mock_checker_class.return_value = mock_checker

        request = _mock_request(query_params={"resource_id": str(self.workspace.id), "resource_type": "workspace"})
        request.method = "GET"
        view = _mock_view("by_subject")

        self.assertTrue(permission.has_permission(request, view))
        mock_checker.check_resource_access.assert_called_once()
        call_kwargs = mock_checker.check_resource_access.call_args[1]
        self.assertEqual(call_kwargs["relation"], "rbac_workspaces_role_binding_view")

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_by_subject_put_checks_grant_and_revoke(self, mock_checker_class, _mock_principal):
        """by_subject PUT should check both GRANT and REVOKE relations."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = True
        mock_checker_class.return_value = mock_checker

        request = _mock_request(query_params={"resource_id": str(self.workspace.id), "resource_type": "workspace"})
        request.method = "PUT"
        view = _mock_view("by_subject")

        self.assertTrue(permission.has_permission(request, view))
        self.assertEqual(mock_checker.check_resource_access.call_count, 2)
        relations_checked = {c[1]["relation"] for c in mock_checker.check_resource_access.call_args_list}
        self.assertEqual(
            relations_checked,
            {"rbac_workspaces_role_binding_grant", "rbac_workspaces_role_binding_revoke"},
        )

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_by_subject_put_denied_when_grant_fails(self, mock_checker_class, _mock_principal):
        """by_subject PUT should be denied when grant check fails."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = False
        mock_checker_class.return_value = mock_checker

        request = _mock_request(query_params={"resource_id": str(self.workspace.id), "resource_type": "workspace"})
        request.method = "PUT"
        view = _mock_view("by_subject")

        self.assertFalse(permission.has_permission(request, view))

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_by_subject_put_denied_when_revoke_fails(self, mock_checker_class, _mock_principal):
        """by_subject PUT should be denied when revoke check fails (grant passes)."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.side_effect = lambda **kwargs: (
            kwargs["relation"] != "rbac_workspaces_role_binding_revoke"
        )
        mock_checker_class.return_value = mock_checker

        request = _mock_request(query_params={"resource_id": str(self.workspace.id), "resource_type": "workspace"})
        request.method = "PUT"
        view = _mock_view("by_subject")

        self.assertFalse(permission.has_permission(request, view))

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_batch_create_checks_grant_relation(self, mock_checker_class, _mock_principal):
        """batch_create should check GRANT_RELATION for each resource."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = True
        mock_checker_class.return_value = mock_checker

        request = _mock_request(data={
            "requests": [
                {"resource": {"type": "workspace", "id": str(self.workspace.id)}, "role": {}, "subject": {}},
            ]
        })
        view = _mock_view("batch_create")

        self.assertTrue(permission.has_permission(request, view))
        mock_checker.check_resource_access.assert_called_once()
        call_kwargs = mock_checker.check_resource_access.call_args[1]
        self.assertEqual(call_kwargs["relation"], "rbac_workspaces_role_binding_grant")
        self.assertEqual(call_kwargs["resource_type"], "workspace")
        self.assertEqual(call_kwargs["resource_id"], str(self.workspace.id))

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_batch_create_checks_all_unique_resources(self, mock_checker_class, _mock_principal):
        """batch_create with multiple resources should check each unique resource."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = True
        mock_checker_class.return_value = mock_checker

        tenant_resource_id = self.tenant.tenant_resource_id()
        request = _mock_request(data={
            "requests": [
                {"resource": {"type": "workspace", "id": str(self.workspace.id)}, "role": {}, "subject": {}},
                {"resource": {"type": "tenant", "id": tenant_resource_id}, "role": {}, "subject": {}},
                {"resource": {"type": "workspace", "id": str(self.workspace.id)}, "role": {}, "subject": {}},
            ]
        })
        view = _mock_view("batch_create")

        self.assertTrue(permission.has_permission(request, view))
        self.assertEqual(mock_checker.check_resource_access.call_count, 2)

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_batch_create_denied_when_any_resource_fails(self, mock_checker_class, _mock_principal):
        """batch_create should be denied when any resource check fails."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.side_effect = lambda **kwargs: kwargs["resource_type"] != "tenant"
        mock_checker_class.return_value = mock_checker

        tenant_resource_id = self.tenant.tenant_resource_id()
        request = _mock_request(data={
            "requests": [
                {"resource": {"type": "workspace", "id": str(self.workspace.id)}, "role": {}, "subject": {}},
                {"resource": {"type": "tenant", "id": tenant_resource_id}, "role": {}, "subject": {}},
            ]
        })
        view = _mock_view("batch_create")

        self.assertFalse(permission.has_permission(request, view))


# ==========================================================================
# Resource type validation and edge cases
# ==========================================================================


@override_settings(V2_APIS_ENABLED=True)
class RoleBindingKesselPermissionResourceTests(RoleBindingAccessTestMixin, TransactionIdentityRequest):
    """Tests for resource type validation and pass-through behavior."""

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_workspace_resource_type_accepted(self, mock_checker_class, _mock_principal):
        """workspace is a valid resource_type."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = True
        mock_checker_class.return_value = mock_checker

        request = _mock_request(query_params={"resource_id": str(self.workspace.id), "resource_type": "workspace"})
        self.assertTrue(permission.has_permission(request, _mock_view("list")))

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_tenant_resource_type_accepted(self, mock_checker_class, _mock_principal):
        """tenant is a valid resource_type and goes through Kessel check."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = True
        mock_checker_class.return_value = mock_checker

        tenant_resource_id = self.tenant.tenant_resource_id()
        request = _mock_request(query_params={"resource_id": tenant_resource_id, "resource_type": "tenant"})

        self.assertTrue(permission.has_permission(request, _mock_view("list")))
        mock_checker.check_resource_access.assert_called_once()
        call_kwargs = mock_checker.check_resource_access.call_args[1]
        self.assertEqual(call_kwargs["resource_type"], "tenant")

    @patch(PRINCIPAL_PATCH)
    @patch(CHECKER_PATCH)
    def test_unknown_resource_type_denied(self, mock_checker_class, mock_principal):
        """Unknown resource_type should be denied without calling Kessel."""
        permission = RoleBindingKesselAccessPermission()
        request = _mock_request(query_params={"resource_id": "some-id", "resource_type": "unknown_type"})

        self.assertFalse(permission.has_permission(request, _mock_view("list")))
        mock_principal.assert_not_called()
        mock_checker_class.assert_not_called()

    def test_no_resource_info_passes_through(self):
        """When no resource info is provided, pass through to view validation."""
        permission = RoleBindingKesselAccessPermission()
        request = _mock_request(query_params={})
        self.assertTrue(permission.has_permission(request, _mock_view("list")))

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_resource_type_normalized_to_lowercase(self, mock_checker_class, _mock_principal):
        """resource_type should be normalized to lowercase."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = True
        mock_checker_class.return_value = mock_checker

        request = _mock_request(query_params={"resource_id": "ws-123", "resource_type": "WORKSPACE"})

        self.assertTrue(permission.has_permission(request, _mock_view("list")))
        call_kwargs = mock_checker.check_resource_access.call_args[1]
        self.assertEqual(call_kwargs["resource_type"], "workspace")

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_nul_bytes_stripped_from_query_params(self, mock_checker_class, _mock_principal):
        """NUL bytes should be stripped from resource_id and resource_type."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = True
        mock_checker_class.return_value = mock_checker

        request = _mock_request(query_params={
            "resource_id": f"\x00{self.workspace.id}\x00",
            "resource_type": "\x00workspace\x00",
        })

        self.assertTrue(permission.has_permission(request, _mock_view("list")))
        call_kwargs = mock_checker.check_resource_access.call_args[1]
        self.assertEqual(call_kwargs["resource_id"], str(self.workspace.id))
        self.assertEqual(call_kwargs["resource_type"], "workspace")

    @patch(PRINCIPAL_PATCH, return_value=None)
    def test_denied_when_principal_id_not_found(self, _mock_principal):
        """Access should be denied when principal_id cannot be determined."""
        permission = RoleBindingKesselAccessPermission()
        request = _mock_request(query_params={"resource_id": str(self.workspace.id), "resource_type": "workspace"})
        self.assertFalse(permission.has_permission(request, _mock_view("list")))

    @patch(PRINCIPAL_PATCH, return_value="localhost/test-user")
    @patch(CHECKER_PATCH)
    def test_denied_when_checker_returns_false(self, mock_checker_class, _mock_principal):
        """Access should be denied when Kessel returns false."""
        permission = RoleBindingKesselAccessPermission()
        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = False
        mock_checker_class.return_value = mock_checker

        request = _mock_request(query_params={"resource_id": str(self.workspace.id), "resource_type": "workspace"})
        self.assertFalse(permission.has_permission(request, _mock_view("list")))

    def test_batch_create_unknown_resource_type_denied(self):
        """batch_create with unknown resource_type in body should be denied."""
        permission = RoleBindingKesselAccessPermission()
        request = _mock_request(data={
            "requests": [
                {"resource": {"type": "unknown", "id": "some-id"}, "role": {}, "subject": {}},
            ]
        })
        self.assertFalse(permission.has_permission(request, _mock_view("batch_create")))

    def test_batch_create_empty_requests_passes_through(self):
        """batch_create with empty requests list should pass through."""
        permission = RoleBindingKesselAccessPermission()
        request = _mock_request(data={"requests": []})
        self.assertTrue(permission.has_permission(request, _mock_view("batch_create")))


# ==========================================================================
# Integration tests (full request flow)
# ==========================================================================


@override_settings(V2_APIS_ENABLED=True)
class RoleBindingAccessIntegrationTests(RoleBindingAccessTestMixin, TransactionIdentityRequest):
    """Integration tests for role binding access with full request flow."""

    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_access_granted_when_inventory_returns_allowed(self, mock_inventory_client):
        """Test that access is granted when Inventory API returns ALLOWED_TRUE."""
        self._setup_kessel_mock(mock_inventory_client, allowed_pb2.Allowed.ALLOWED_TRUE)

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        headers = request_context["request"].META

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace",
            **headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_access_denied_when_inventory_returns_not_allowed(self, mock_inventory_client):
        """Test that access is denied when Inventory API returns ALLOWED_FALSE."""
        self._setup_kessel_mock(mock_inventory_client, allowed_pb2.Allowed.ALLOWED_FALSE)

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        headers = request_context["request"].META

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace",
            **headers,
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_check_uses_view_relation_for_get(self, mock_inventory_client):
        """Test that GET by_subject uses rbac_workspaces_role_binding_view relation."""
        mock_stub, _ = self._setup_kessel_mock(mock_inventory_client)

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        headers = request_context["request"].META

        url = self._get_by_subject_url()
        self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace",
            **headers,
        )

        mock_stub.CheckForUpdate.assert_called_once()
        call_args = mock_stub.CheckForUpdate.call_args
        request_obj = call_args[0][0]
        self.assertEqual(request_obj.relation, "rbac_workspaces_role_binding_view")

    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_check_uses_correct_workspace_id(self, mock_inventory_client):
        """Test that the permission check uses the correct workspace ID."""
        mock_stub, _ = self._setup_kessel_mock(mock_inventory_client)

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        headers = request_context["request"].META

        url = self._get_by_subject_url()
        self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace",
            **headers,
        )

        mock_stub.CheckForUpdate.assert_called_once()
        call_args = mock_stub.CheckForUpdate.call_args
        request_obj = call_args[0][0]
        self.assertEqual(request_obj.object.resource_id, str(self.workspace.id))
        self.assertEqual(request_obj.object.resource_type, "workspace")

    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_access_denied_on_inventory_connectivity_error(self, mock_inventory_client):
        """Test that access is denied when Inventory API is unreachable."""
        import grpc

        mock_inventory_client.return_value.__enter__.side_effect = grpc.RpcError()

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        headers = request_context["request"].META

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace",
            **headers,
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_unexpected_allowed_status_returns_false(self, mock_inventory_client):
        """Test that unexpected allowed status from Inventory API returns False."""
        self._setup_kessel_mock(mock_inventory_client, allowed_pb2.Allowed.ALLOWED_UNSPECIFIED)

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        headers = request_context["request"].META

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace",
            **headers,
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_nul_bytes_stripped_from_resource_id(self, mock_inventory_client):
        """Test that NUL bytes are stripped from resource_id in permission check."""
        self._setup_kessel_mock(mock_inventory_client)

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        headers = request_context["request"].META

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id=\x00{self.workspace.id}\x00&resource_type=workspace",
            **headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)


# ==========================================================================
# Principal lookup tests (unchanged logic, tests still valid)
# ==========================================================================


@override_settings(V2_APIS_ENABLED=True)
class RoleBindingPrincipalLookupTests(RoleBindingAccessTestMixin, TransactionIdentityRequest):
    """Unit tests for principal lookup logic via get_kessel_principal_id utility."""

    @patch("management.utils.get_principal_from_request", return_value=None)
    @patch("management.principal.proxy.PrincipalProxy")
    def test_principal_lookup_fails_when_it_service_returns_non_200(self, mock_proxy_class, mock_get_principal):
        """Test that access is denied when IT service returns non-200 status."""
        permission = RoleBindingKesselAccessPermission()

        mock_proxy = MagicMock()
        mock_proxy.request_filtered_principals.return_value = {"status_code": 500, "data": []}
        mock_proxy_class.return_value = mock_proxy

        mock_request = Mock()
        mock_request.user.system = False
        mock_request.user.admin = False
        mock_request.user.user_id = None
        mock_request.user.username = "testuser"
        mock_request.user.org_id = "test-org"
        mock_request.query_params = {"resource_id": str(self.workspace.id), "resource_type": "workspace"}

        self.assertFalse(permission.has_permission(mock_request, _mock_view("list")))

    @patch("management.utils.get_principal_from_request", return_value=None)
    @patch("management.principal.proxy.PrincipalProxy")
    def test_principal_lookup_fails_when_it_service_returns_empty_data(self, mock_proxy_class, mock_get_principal):
        """Test that access is denied when IT service returns empty data."""
        permission = RoleBindingKesselAccessPermission()

        mock_proxy = MagicMock()
        mock_proxy.request_filtered_principals.return_value = {"status_code": 200, "data": []}
        mock_proxy_class.return_value = mock_proxy

        mock_request = Mock()
        mock_request.user.system = False
        mock_request.user.admin = False
        mock_request.user.user_id = None
        mock_request.user.username = "testuser"
        mock_request.user.org_id = "test-org"
        mock_request.query_params = {"resource_id": str(self.workspace.id), "resource_type": "workspace"}

        self.assertFalse(permission.has_permission(mock_request, _mock_view("list")))

    @patch("management.utils.get_principal_from_request", return_value=None)
    @patch("management.principal.proxy.PrincipalProxy")
    def test_principal_lookup_fails_when_it_service_response_missing_user_id(
        self, mock_proxy_class, mock_get_principal
    ):
        """Test that access is denied when IT service response lacks user_id."""
        permission = RoleBindingKesselAccessPermission()

        mock_proxy = MagicMock()
        mock_proxy.request_filtered_principals.return_value = {
            "status_code": 200,
            "data": [{"username": "testuser"}],
        }
        mock_proxy_class.return_value = mock_proxy

        mock_request = Mock()
        mock_request.user.system = False
        mock_request.user.admin = False
        mock_request.user.user_id = None
        mock_request.user.username = "testuser"
        mock_request.user.org_id = "test-org"
        mock_request.query_params = {"resource_id": str(self.workspace.id), "resource_type": "workspace"}

        self.assertFalse(permission.has_permission(mock_request, _mock_view("list")))

    @patch("management.utils.get_principal_from_request", return_value=None)
    def test_principal_lookup_fails_when_request_user_missing_username(self, mock_get_principal):
        """Test that access is denied when request.user is missing username."""
        permission = RoleBindingKesselAccessPermission()

        mock_request = Mock()
        mock_request.user.system = False
        mock_request.user.admin = False
        mock_request.user.user_id = None
        mock_request.user.username = None
        mock_request.user.org_id = "test-org"
        mock_request.query_params = {"resource_id": str(self.workspace.id), "resource_type": "workspace"}

        self.assertFalse(permission.has_permission(mock_request, _mock_view("list")))

    @patch("management.utils.get_principal_from_request", return_value=None)
    def test_principal_lookup_fails_when_request_user_missing_org_id(self, mock_get_principal):
        """Test that access is denied when request.user is missing org_id."""
        permission = RoleBindingKesselAccessPermission()

        mock_request = Mock()
        mock_request.user.system = False
        mock_request.user.admin = False
        mock_request.user.user_id = None
        mock_request.user.username = "testuser"
        mock_request.user.org_id = None
        mock_request.query_params = {"resource_id": str(self.workspace.id), "resource_type": "workspace"}

        self.assertFalse(permission.has_permission(mock_request, _mock_view("list")))

    @patch("management.utils.get_principal_from_request", return_value=None)
    @patch("management.principal.proxy.PrincipalProxy")
    def test_principal_lookup_fails_when_it_service_raises_request_exception(
        self, mock_proxy_class, mock_get_principal
    ):
        """Test that access is denied when PrincipalProxy raises a network error."""
        permission = RoleBindingKesselAccessPermission()

        mock_proxy = MagicMock()
        mock_proxy.request_filtered_principals.side_effect = requests.exceptions.ConnectionError("Network error")
        mock_proxy_class.return_value = mock_proxy

        mock_request = Mock()
        mock_request.user.system = False
        mock_request.user.admin = False
        mock_request.user.user_id = None
        mock_request.user.username = "testuser"
        mock_request.user.org_id = "test-org"
        mock_request.query_params = {"resource_id": str(self.workspace.id), "resource_type": "workspace"}

        self.assertFalse(permission.has_permission(mock_request, _mock_view("list")))

    @patch("management.utils.get_principal_from_request")
    @patch("management.principal.proxy.PrincipalProxy")
    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_principal_lookup_fast_path_from_principal(
        self, mock_inventory_client, mock_proxy_class, mock_get_principal
    ):
        """Test fast path when get_principal_from_request returns a Principal with user_id."""
        permission = RoleBindingKesselAccessPermission()

        mock_principal = Mock()
        mock_principal.user_id = "principal-user-123"
        mock_get_principal.return_value = mock_principal

        self._setup_kessel_mock(mock_inventory_client)

        mock_request = Mock()
        mock_request.user.system = False
        mock_request.user.admin = False
        mock_request.query_params = {"resource_id": str(self.workspace.id), "resource_type": "workspace"}

        mock_view = _mock_view("list")

        self.assertTrue(permission.has_permission(mock_request, mock_view))
        mock_get_principal.assert_called_once()
        mock_proxy_class.assert_not_called()

    @patch("management.utils.get_principal_from_request", return_value=None)
    @patch("management.principal.proxy.PrincipalProxy")
    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_principal_lookup_fast_path_from_request_user(
        self, mock_inventory_client, mock_proxy_class, mock_get_principal
    ):
        """Test fast path when request.user.user_id is set."""
        permission = RoleBindingKesselAccessPermission()

        self._setup_kessel_mock(mock_inventory_client)

        mock_request = Mock()
        mock_request.user.system = False
        mock_request.user.admin = False
        mock_request.user.user_id = "request-user-123"
        mock_request.query_params = {"resource_id": str(self.workspace.id), "resource_type": "workspace"}

        mock_view = _mock_view("list")

        self.assertTrue(permission.has_permission(mock_request, mock_view))
        mock_proxy_class.assert_not_called()


# ==========================================================================
# Service account tests
# ==========================================================================


@override_settings(V2_APIS_ENABLED=True)
class RoleBindingServiceAccountTests(RoleBindingAccessTestMixin, TransactionIdentityRequest):
    """Tests for service account access to role bindings."""

    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_service_account_goes_through_kessel_check(self, mock_inventory_client):
        """Test that service accounts go through Kessel permission check."""
        self._setup_kessel_mock(mock_inventory_client)

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        request_context["request"].user.username = "service-account-12345678-1234-1234-1234-123456789012"
        headers = request_context["request"].META

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace",
            **headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_inventory_client.assert_called()

    @patch("management.permissions.workspace_inventory_access.inventory_client")
    def test_service_account_denied_when_kessel_returns_false(self, mock_inventory_client):
        """Test that service accounts are denied when Kessel returns ALLOWED_FALSE."""
        self._setup_kessel_mock(mock_inventory_client, allowed_pb2.Allowed.ALLOWED_FALSE)

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        request_context["request"].user.username = "service-account-12345678-1234-1234-1234-123456789012"
        headers = request_context["request"].META

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace",
            **headers,
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch(PRINCIPAL_PATCH, return_value="localhost/sa-user-123")
    @patch(CHECKER_PATCH)
    def test_service_account_permission_uses_kessel_checker(self, mock_checker_class, _mock_principal):
        """Test that service account permission check uses correct relation."""
        permission = RoleBindingKesselAccessPermission()

        mock_checker = MagicMock()
        mock_checker.check_resource_access.return_value = True
        mock_checker_class.return_value = mock_checker

        mock_request = _mock_request(
            query_params={"resource_id": str(self.workspace.id), "resource_type": "workspace"}
        )

        self.assertTrue(permission.has_permission(mock_request, _mock_view("list")))
        mock_checker.check_resource_access.assert_called_once()
        call_kwargs = mock_checker.check_resource_access.call_args[1]
        self.assertEqual(call_kwargs["relation"], "rbac_workspaces_role_binding_view")
        self.assertEqual(call_kwargs["principal_id"], "localhost/sa-user-123")

    @patch(PRINCIPAL_PATCH, return_value=None)
    @patch(CHECKER_PATCH)
    def test_service_account_denied_when_principal_id_not_found(self, mock_checker_class, _mock_principal):
        """Test that service account is denied when principal_id cannot be determined."""
        permission = RoleBindingKesselAccessPermission()

        mock_request = _mock_request(
            query_params={"resource_id": str(self.workspace.id), "resource_type": "workspace"}
        )

        self.assertFalse(permission.has_permission(mock_request, _mock_view("list")))
        mock_checker_class.assert_not_called()
