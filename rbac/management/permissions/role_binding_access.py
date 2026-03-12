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

"""Role binding access permissions using Kessel Inventory API."""

import logging

from management.permissions.workspace_inventory_access import (
    WorkspaceInventoryAccessChecker,
)
from management.principal.proxy import get_kessel_principal_id
from rest_framework import permissions

logger = logging.getLogger(__name__)


def _is_system_user_without_admin(user) -> bool:
    """
    Check if user is a system user without admin privileges.

    Args:
        user: The user object from the request

    Returns:
        bool: True if user is system but not admin, False otherwise
    """
    is_system = getattr(user, "system", False)
    is_admin = getattr(user, "admin", False)
    return is_system and not is_admin


class RoleBindingSystemUserAccessPermission(permissions.BasePermission):
    """
    Permission class for system user access to role bindings.

    Checks if system users (s2s communication) have proper access.
    Non-admin system users are denied.
    All other users (including admins) pass through to next permission class.
    """

    def has_permission(self, request, view):
        """
        Check if user has access based on system user status.

        Args:
            request: The HTTP request object
            view: The view being accessed

        Returns:
            bool: True to pass through to next permission, False if denied
        """
        user = request.user

        # System users without admin are denied
        if _is_system_user_without_admin(user):
            return False

        # All other users pass through to next permission class (Kessel check)
        return True


class RoleBindingKesselAccessPermission(permissions.BasePermission):
    """
    Permission class for role binding access using Kessel Inventory API.

    Checks action-specific relations against the target resource(s):

    - List / list-by-subject (GET): rbac_workspaces_role_binding_view
    - Update by subject (PUT):     rbac_workspaces_role_binding_grant AND
                                    rbac_workspaces_role_binding_revoke
    - Batch create (POST):         rbac_workspaces_role_binding_grant

    The resource may be a workspace or tenant. For batch_create the resources
    are read from the request body; for all other actions they come from
    query parameters.

    This permission class should be used after RoleBindingSystemUserAccessPermission
    which handles system user denial logic.
    """

    GRANT_RELATION = "rbac_workspaces_role_binding_grant"
    REVOKE_RELATION = "rbac_workspaces_role_binding_revoke"
    VIEW_RELATION = "rbac_workspaces_role_binding_view"

    ALLOWED_RESOURCE_TYPES = {"workspace", "tenant"}

    def _get_relations(self, view, request) -> list[str]:
        """Return the relation(s) that must ALL pass for the current action."""
        action = getattr(view, "action", None)
        if action == "batch_create":
            return [self.GRANT_RELATION]
        if action == "by_subject" and request.method == "PUT":
            return [self.GRANT_RELATION, self.REVOKE_RELATION]
        return [self.VIEW_RELATION]

    def _get_resources(self, request, view) -> list[tuple[str, str]]:
        """Extract (resource_type, resource_id) pairs for the permission check."""
        action = getattr(view, "action", None)
        if action == "batch_create":
            return self._get_resources_from_body(request)
        return self._get_resources_from_query_params(request)

    def _get_resources_from_body(self, request) -> list[tuple[str, str]]:
        """Extract unique resources from the batch_create request body."""
        requests_data = request.data.get("requests", [])
        resources: set[tuple[str, str]] = set()
        for item in requests_data:
            resource = item.get("resource", {})
            resource_type = resource.get("type", "").lower()
            resource_id = str(resource.get("id", ""))
            if resource_type and resource_id:
                resources.add((resource_type, resource_id))
        return list(resources)

    def _get_resources_from_query_params(self, request) -> list[tuple[str, str]]:
        """Extract a single resource from query parameters."""
        resource_id = request.query_params.get("resource_id", "").replace("\x00", "")
        resource_type = request.query_params.get("resource_type", "").replace("\x00", "").lower()
        if not resource_id or not resource_type:
            return []
        return [(resource_type, resource_id)]

    def has_permission(self, request, view):
        """
        Check if the user has permission to access role bindings.

        For each target resource, every required relation must be granted.
        """
        resources = self._get_resources(request, view)

        if not resources:
            return True

        for resource_type, _ in resources:
            if resource_type not in self.ALLOWED_RESOURCE_TYPES:
                logger.debug("Denied access for unknown resource_type: %s", resource_type)
                return False

        principal_id = get_kessel_principal_id(request)
        if not principal_id:
            return False

        relations = self._get_relations(view, request)
        checker = WorkspaceInventoryAccessChecker()

        for resource_type, resource_id in resources:
            for relation in relations:
                if not checker.check_resource_access(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    principal_id=principal_id,
                    relation=relation,
                ):
                    return False

        return True
