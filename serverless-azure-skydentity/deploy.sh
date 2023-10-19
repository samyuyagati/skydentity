# Azure CLI
# Set resource group name to 'skydentiy', app name to 'skydentity-proxy', 
# target port to '5000' to match Dockerfile

# For secret mount, added from reference here: https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets?tabs=azure-cli#example-1 
# Not sure if this works for az containerapp up
az containerapp up \
  --resource-group skydentity --name skydentity-proxy \
  --ingress external --target-port 5000 --source .
  --secrets "queue-connection-string=$CONNECTIONSTRING" "api-key=$API_KEY" \
  --secret-volume-mount "/mnt/secrets"