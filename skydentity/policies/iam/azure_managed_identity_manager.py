import uuid

#import httplib2
#httplib2.debuglevel = 4
from azure.identity import DefaultAzureCredential
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.msi.models import Identity
from azure.mgmt.authorization.models import RoleDefinition, RoleAssignmentCreateParameters
from azure.mgmt.authorization import AuthorizationManagementClient
from skydentity.policies.checker.azure_authorization_policy import AzureAuthorizationPolicy, AzureAuthorization, RestrictedRole

class MockRoleDefinition:

    def __init__(self, id) -> None:
        self.id = id

class AzureManagedIdentityManager:

    def __init__(self, subscription_id) -> None:
        """
        :param subscription_id: Azure subscription id
        """
        self._managed_identities = {}
        self._role_assignments = {}
        self._credentials = DefaultAzureCredential()
        self._managed_identity_client = ManagedServiceIdentityClient(self._credentials, subscription_id)
        self._authorization_client = AuthorizationManagementClient(self._credentials, subscription_id)
        self._subscription_id = subscription_id

    def create_managed_identity(self, authorization: AzureAuthorizationPolicy, managed_identity_name: str) -> str:
        """
        Attempts to get or create a managed identity given its name and returns the fully qualified id.
        """
        auth: AzureAuthorization = authorization._policy

        # Create service account if it doesn't exist
        local_managed_identity_key = (managed_identity_name, auth.resource_group)
        if local_managed_identity_key not in self._managed_identities:
            
            # Check if service account exists
            try:
                self._managed_identities[local_managed_identity_key] = self._managed_identity_client.user_assigned_identities.get(
                    resource_group_name=auth.resource_group,
                    resource_name=managed_identity_name
                )
            except:
                self._managed_identities[local_managed_identity_key] = (
                    self._managed_identity_client.user_assigned_identities.create_or_update(
                        resource_group_name=auth.resource_group,
                        resource_name=managed_identity_name,
                        parameters=Identity(location=auth.region)
                    )
                )
        return self._managed_identities[local_managed_identity_key].id
    
    def duplicate_managed_identity_in_different_resource_group(self, source_resource_group: str, managed_identity_name: str, new_resource_group: str) -> str:
        """
        Duplicates a managed identity in a different resource group.
        """
        # Check if source managed identity exists
        local_managed_identity_key = (managed_identity_name, source_resource_group)
        source_managed_identity = None
        if local_managed_identity_key in self._managed_identities:
            source_managed_identity = self._managed_identities[local_managed_identity_key]
        else:
            try:                
                source_managed_identity = self._managed_identity_client.user_assigned_identities.get(
                    source_resource_group,
                    managed_identity_name
                )
            except:
                raise ValueError(f"Managed identity {managed_identity_name} does not exist in resource group {source_resource_group}")

        managed_identity_role_assignments = None
        if local_managed_identity_key in self._role_assignments:
            managed_identity_role_assignments = self._role_assignments[local_managed_identity_key]
        else:
            managed_identity_role_assignments = []
            page_of_assignments = self._authorization_client.role_assignments.list_for_resource_group(
                source_resource_group,
                filter=f"principalId eq '{source_managed_identity.principal_id}'"
            )
            for role_assignment in page_of_assignments:
                managed_identity_role_assignments.append(role_assignment)
            self._role_assignments[local_managed_identity_key] = managed_identity_role_assignments

        # Create managed identity in new resource group with a request
        new_managed_identity = self._managed_identity_client.user_assigned_identities.create_or_update(
            resource_group_name=new_resource_group,
            resource_name=managed_identity_name,
            parameters=Identity(location=source_managed_identity.location)
        )

        # Assign roles to new managed identity
        for role_assignment in managed_identity_role_assignments:
            self._authorization_client.role_assignments.create(
                scope=role_assignment.scope.replace(source_resource_group, new_resource_group),
                role_assignment_name=str(uuid.uuid4()),
                parameters=RoleAssignmentCreateParameters(
                    role_definition_id=role_assignment.role_definition_id,
                    principal_id=new_managed_identity.principal_id,
                    principal_type="ServicePrincipal",
                    condition=role_assignment.condition,
                    condition_version=role_assignment.condition_version
                )
            )

    def add_roles_to_managed_identity(self, authorization: AzureAuthorizationPolicy, managed_identity_name):
        auth: AzureAuthorization = authorization._policy
        
        managed_identity = None
        local_managed_identity_key = (managed_identity_name, auth.resource_group)
        if local_managed_identity_key in self._managed_identities:
            managed_identity = self._managed_identities[local_managed_identity_key]
        else:
            try:
                managed_identity = self._managed_identity_client.user_assigned_identities.get(
                    resource_group_name=auth.resource_group,
                    identity_name=managed_identity_name
                )
                self._managed_identities[local_managed_identity_key] = managed_identity
            except:
                raise ValueError(f"Managed identity {managed_identity_name} does not exist in resource group {auth.resource_group}")

        # Get current policy to modify and add roles
        print("Resource Group:", auth.resource_group)

        # Strategy for creating Managed Identity with roles and granular conditions is to first create the roles, then assign roles to managed identity with conditions

        azure_role_objects = []
        # TODO(kdharmarajan): Later prioritization but can optimize this to group by condition and then create roles in bulk with fewer requests
        for i, new_binding in enumerate(auth.roles):
            # Skip role creation if it is an existing role in Azure
            if "roleDefinitions" in new_binding.role:
                role_id = f"/subscriptions/{self._subscription_id}/resourceGroups/{auth.resource_group}/providers/{new_binding.role}"
                azure_role_objects.append(MockRoleDefinition(role_id))
                continue

            permissions = [
                {
                    "actions": [],
                    "notActions": [],
                    "dataActions": [],
                    "notDataActions": [],
                    "conditions": []
                }
            ]

            # Azure has a distinction between actions and data actions, where the later is for reading/writing blobs,
            # so we need to handle that here.
            if "blobs" in new_binding.role:
                permissions[0]["dataActions"].append(new_binding.role)
            else:
                permissions[0]["actions"].append(new_binding.role)

            managed_identity_id_suffix = managed_identity.id.split("/")[-1]

            role_definition = RoleDefinition(
                assignable_scopes=[f"/subscriptions/{self._subscription_id}/resourceGroups/{auth.resource_group}"],
                role_name=f"{managed_identity_id_suffix}_Custom_Role_{i}",
                description="Skydentity created custom role",
                permissions=permissions
            )

            role_definition = self._authorization_client.role_definitions.create_or_update(
                scope=f"/subscriptions/{self._subscription_id}/resourceGroups/{auth.resource_group}",
                role_definition_id=str(uuid.uuid4()),
                role_definition=role_definition
            )

            azure_role_objects.append(role_definition)

        print("Created role definitions")
        self._role_assignments[local_managed_identity_key] = []
        for i, new_binding in enumerate(auth.roles):
            azure_role = azure_role_objects[i]

            binding_resource_group = auth.resource_group
            if new_binding.scope == "resource_group":
                binding_resource_group = new_binding.object

            possible_condition = self.get_object_condition(new_binding)
            print("Condition to assign is", possible_condition)
            # Assign role to service account
            role_assignment = self._authorization_client.role_assignments.create(
                scope=f"/subscriptions/{self._subscription_id}/resourceGroups/{binding_resource_group}",
                role_assignment_name=str(uuid.uuid4()),
                parameters=RoleAssignmentCreateParameters(
                    role_definition_id=azure_role.id,
                    principal_id=managed_identity.principal_id,
                    principal_type="ServicePrincipal",
                    condition=possible_condition,
                    condition_version="2.0" if possible_condition else None
                ))
            self._role_assignments[local_managed_identity_key].append(role_assignment)
            print("Good role assignment")
        print("Assigned roles")


    def get_object_condition(self, binding):
        """
        Since Azure requires conditions for reading from a container, we need to create a condition for that,
        and this provides that template.
        """
        if binding.scope == "resource_group":
            return None
        elif binding.scope == "container":
            return f"@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals '{binding.object}'"
        else:
            raise ValueError(f"Unsupported object {binding.object}")