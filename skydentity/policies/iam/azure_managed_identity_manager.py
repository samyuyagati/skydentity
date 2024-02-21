import uuid

#import httplib2
#httplib2.debuglevel = 4
from azure.identity import DefaultAzureCredential
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.msi.models import Identity
from azure.mgmt.authorization.models import RoleDefinition, RoleAssignmentCreateParameters
from azure.mgmt.authorization import AuthorizationManagementClient
from skydentity.policies.checker.azure_authorization_policy import AzureAuthorizationPolicy, AzureAuthorization, RestrictedRole


class AzureManagedIdentityManager:

    def __init__(self, subscription_id) -> None:
        """
        :param subscription_id: Azure subscription id
        """
        self._managed_identities = {}
        self._credentials = DefaultAzureCredential()
        self._managed_identity_client = ManagedServiceIdentityClient(self._credentials, subscription_id)
        self._authorization_client = AuthorizationManagementClient(self._credentials, subscription_id)
        self._subscription_id = subscription_id

    def create_managed_identity(self, authorization: AzureAuthorizationPolicy, managed_identity_name: str):
        auth: AzureAuthorization = authorization._policy

        # Create service account if it doesn't exist
        if managed_identity_name not in self._managed_identities:
            
            # Check if service account exists
            try:
                self._managed_identity_client.user_assigned_identities.get(
                    resource_group_name=auth.resource_group,
                    resource_name=managed_identity_name
                )
                return
            except:
                self._managed_identities[managed_identity_name] = (
                    self._managed_identity_client.user_assigned_identities.create_or_update(
                        resource_group_name=auth.resource_group,
                        resource_name=managed_identity_name,
                        parameters=Identity(location=auth.region)
                    )
                )


    def add_roles_to_managed_identity(self, authorization: AzureAuthorizationPolicy, managed_identity_name):
        auth: AzureAuthorization = authorization._policy
        
        managed_identity = None
        if managed_identity_name in self._managed_identities:
            managed_identity = self._managed_identities[managed_identity_name]
        else:
            try:
                managed_identity = self._managed_identity_client.user_assigned_identities.get(
                    resource_group_name=auth.resource_group,
                    identity_name=managed_identity_name
                )
                self._managed_identities[managed_identity_name] = managed_identity
            except:
                raise ValueError(f"Managed identity {managed_identity_name} does not exist in resource group {auth.resource_group}")

        # Get current policy to modify and add roles
        print("Resource Group:", auth.resource_group)
        permissions = [
            {
                "actions": [],
                "notActions": [],
                "dataActions": [],
                "notDataActions": [],
                "conditions": []
            }
        ]      
        for new_binding in auth.roles:

            possible_condition = self.get_object_condition(new_binding)
            # TODO: Fix inserting conditions for a role
            if possible_condition:
                permissions[0]["conditions"].append(possible_condition)

            # Azure has a distinction between actions and data actions, where the later is for reading/writing blobs,
            # so we need to handle that here.
            if "blobs" in new_binding.role:
                permissions[0]["dataActions"].append(new_binding.role)
            else:
                permissions[0]["actions"].append(new_binding.role)

        role_definition = RoleDefinition(
            assignable_scopes=[f"/subscriptions/{self._subscription_id}/resourceGroups/{auth.resource_group}"],
            role_name=f"{managed_identity.id}_Custom_Role",
            description="Skydentity created custom role",
            permissions=permissions
        )

        role_definition = self._authorization_client.role_definitions.create_or_update(
            scope=f"/subscriptions/{self._subscription_id}/resourceGroups/{auth.resource_group}",
            role_definition_id=str(uuid.uuid4()),
            role_definition=role_definition
        )

        # Assign role to service account
        role_assignment = self._authorization_client.role_assignments.create(
            scope=f"/subscriptions/{self._subscription_id}/resourceGroups/{auth.resource_group}",
            role_assignment_name=str(uuid.uuid4()),
            parameters=RoleAssignmentCreateParameters(
                role_definition_id=role_definition.id,
                principal_id=managed_identity.principal_id,
                principal_type="ServicePrincipal"
            ))


    def get_object_condition(self, binding):
        """
        Since Azure requires conditions for reading from a container, we need to create a condition for that,
        and this provides that template.
        """
        if binding.scope == "project":
            return None
        elif binding.scope == "container":
            return {
                "operator": "Equals",
                "values": [binding.object],
                "data": {
                    "field": "Microsoft.Storage/storageAccounts/blobServices/containers/name"
                }
            }
        else:
            raise ValueError(f"Unsupported object {binding.object}")