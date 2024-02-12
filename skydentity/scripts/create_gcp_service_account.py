import argparse
from skydentity.policies.iam.gcp_service_account_manager import GCPServiceAccountManager

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--project_id', type=str, help='Project ID where the service account will be')
    parser.add_argument('--service_account_name', type=str, help='Name of the service account to be created')
    parser.add_argument('--display_name', type=str, help='Display name of the service account to be created')
    parser.add_argument('--roles', nargs='+', help='Roles to be assigned to the service account')
    parser.add_argument('--credentials', type=str, help='Path to service account json')
    args = parser.parse_args()

    gcp_service_account_manager = GCPServiceAccountManager(credentials_path=args.credentials)
    gcp_service_account_manager.create_service_account(args.project_id, 
                                                       args.service_account_name, 
                                                       args.display_name)
    gcp_service_account_manager.add_roles_to_service_account(args.project_id, 
                                                             args.service_account_name, 
                                                             args.roles)