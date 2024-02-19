<#
.SYNOPSIS
    This script sets up management logging for Azure resources in a specified management group.
.DESCRIPTION
    The script installs the required modules, connects to Azure using interactive login, and retrieves all log analytics workspaces and management groups.
    It then prompts the user to select a log analytics workspace and a management group.
    Finally, it updates the diagnostic settings for the selected management group to enable logging for administrative and policy categories.
.PARAMETER TenantId
    The ID of the Azure AD tenant to use for authentication. If not provided, a default tenant ID is used.
.EXAMPLE
    .\SetupManagmentLogging.ps1 -TenantId "xxxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxx-xxxxxxxxxxxxx"
    This example runs the script using the specified tenant ID.
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$TenantId
)

Write-Host "Installing required modules..."
Install-Module -Name Az.OperationalInsights,Az.Accounts -Scope CurrentUser

if (-not $TenantId) {
    Write-Host "Connecting to Azure using interactive login..."
    Connect-AzAccount
} else {
    Write-Host "Connecting to Azure using interactive login with TenantId: $TenantId..."
    Connect-AzAccount -TenantId $TenantId
}

# Check if the login was successful
if (Get-AzContext) {
    Write-Host "Logged in to Azure successfully."
} else {
    Write-Host "Failed to log in to Azure."
}

$managementGroups = Get-AzManagementGroup

# Get all subscriptions
$subscriptions = Get-AzSubscription -tenantId $TenantId

# Create an empty array to store log analytics workspaces
$logAnalyticsWorkspaces = @()

# Loop through each subscription
foreach ($subscription in $subscriptions) {
    # Set the current subscription context
    Set-AzContext -SubscriptionId $subscription.Id

    # Get all log analytics workspaces in the current subscription
    $workspaces = Get-AzOperationalInsightsWorkspace

    # Loop through each workspace and add it to the array
    foreach ($workspace in $workspaces) {
        # Add the workspace to the array
        $logAnalyticsWorkspaces += $workspace
    }
}

$SelectedAnalyticsWorkspaces = $logAnalyticsWorkspaces | Out-GridView -PassThru -Title "Select Log Analytics Workspace"
$SelectedManagementGroup = $managementGroups | Out-GridView -PassThru -Title "Select Management Group"

foreach ($managementGroup in $SelectedManagementGroup) {
    # Send the PUT request (https://learn.microsoft.com/en-us/rest/api/monitor/management-group-diagnostic-settings/create-or-update?view=rest-monitor-2020-01-01-preview&tabs=HTTP)
    $apiEndpoint = "https://management.azure.com/providers/microsoft.management/managementGroups/$($managementGroup.Name)/providers/microsoft.insights/diagnosticSettings/setting1?api-version=2020-01-01-preview"

    $Payload = @{
        "properties" = @{
            "workspaceId" = "$($SelectedAnalyticsWorkspaces.ResourceId)"
            "logs" = @(
                @{
                    "category" = "Administrative"
                    "enabled" = $true
                },
                @{
                    "category" = "Policy"
                    "enabled" = $true
                }
            )
        }
    } | ConvertTo-Json -Depth 3

    Write-Host "Updating diagnostic settings for management group $($managementGroup.Name)..."
    Invoke-AzRestMethod -Method Put -Uri $apiEndpoint -Payload $Payload
}


#Validating the diagnostic settings

$apiResponseArray = @()
# Loop through each selected management group
foreach ($managementGroup in $SelectedManagementGroup) {
    # Send the PUT request
    $apiEndpoint = "https://management.azure.com/providers/microsoft.management/managementGroups/$($managementGroup.Name)/providers/microsoft.insights/diagnosticSettings/setting1?api-version=2020-01-01-preview"

    Write-Host "Reading diagnostic settings for management group $($managementGroup.Name)..."
    $apiResponse = Invoke-AzRestMethod -Method GET -Uri $apiEndpoint
    $apiResponseArray += $apiResponse
}

# Loop through each API response
foreach ($apiResponse in $apiResponseArray) {
    Write-Host $apiResponse.Content
}
