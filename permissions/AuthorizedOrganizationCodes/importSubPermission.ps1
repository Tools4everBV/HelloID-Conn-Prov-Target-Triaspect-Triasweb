################################################################
# HelloID-Conn-Prov-Target-Triaspect-Triasweb-ImportSubPermission-Authorization-Organization-Codes
# PowerShell V2
################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Configure, must be the same as the values used in retrieve permissions
$permissionReference = 'authorizationOrganizationCodes'
$permissionDisplayName = 'authorizationOrganizationCodes'

#region functions
function Resolve-TriaswebError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            if ($null -ne $errorDetailsObject.Details) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.Details
            }
            elseif ($null -ne $errorDetailsObject.error) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = "Error: [$($httpErrorObj.ErrorDetails)] [$($_.Exception.Message)]"
        }
        Write-Output $httpErrorObj
    }
}
#endregion

try {
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($actionContext.Configuration.CertificatePath, $actionContext.Configuration.CertificatePassword, 'UserKeySet')
    if ($certificate.NotAfter -le (Get-Date)) {
        throw "Certificate has expired on $($certificate.NotAfter)..."
    }

    $splatTokenParams = @{
        Uri         = "$($actionContext.Configuration.TokenBaseUrl)/connect/token"
        Method      = 'POST'
        Certificate = $certificate
        Headers     = @{
            'content-type' = 'application/x-www-form-urlencoded'
        }
        Body        = @{
            client_id     = $actionContext.Configuration.ClientID
            client_secret = $actionContext.Configuration.ClientSecret
            grant_type    = 'client_credentials'
        }
    }
    $accessToken = (Invoke-RestMethod @splatTokenParams).access_token

    $headers = @{
        Authorization  = "Bearer $($accessToken)"
        'content-type' = 'application/json'
    }

    Write-Information 'Starting permission data import'
    $pageSize = 50
    $pageNumber = 1
    $importedAccounts = [System.Collections.Generic.List[object]]::new()
    do {
        $splatGetUsers = @{
            Uri         = "$($actionContext.Configuration.BaseUrl)/api/users/list?pageNumber=$($pageNumber)&pageSize=$($pageSize)"
            Method      = 'Get'
            Certificate = $certificate
            Headers     = $headers
        }
        $response = Invoke-RestMethod @splatGetUsers

        if ($response.data) {
            $importedAccounts.AddRange($response.data)
        }

        $pageNumber++
    } while ($pageNumber -le $response.totalPages)

    # Retrieve all unique authorizedOrganizationCodes from accounts property in accounts.
    $importedPermissions = @{}
    foreach ($importedAccount in $importedAccounts) {
        foreach ($authorizedOrganizationCodes in $importedAccount.authorizedOrganizationCodes) {
            if (![string]::IsNullOrWhiteSpace($authorizedOrganizationCodes)) {
                if (-not $importedPermissions.ContainsKey($authorizedOrganizationCodes)) {
                    $importedPermissions[$authorizedOrganizationCodes] = @()
                }
                if ($importedAccount.id -notin $importedPermissions[$authorizedOrganizationCodes]) {
                    $importedPermissions[$authorizedOrganizationCodes] += $importedAccount.id
                }
            }
        }
    }

    foreach ($importedPermission in $importedPermissions.GetEnumerator()) {
        $subPermissionDisplayName = $($importedPermission.Key).substring(0, [System.Math]::Min(100, $($importedPermission.Key).Length))
        $permission = @{
            PermissionReference      = @{
                Reference = $permissionReference
            }       
            DisplayName              = $permissionDisplayName
            AccountReferences        = $importedPermission.Value
            SubPermissionReference   = @{
                Id = $importedPermission.Key
            }
            SubPermissionDisplayName = $subPermissionDisplayName
        }

        $membersOfRetrievedPermission = [System.Collections.Generic.List[string]]($importedPermission.Value)
        # Batch permissions based on AccountReference to ensure the output object do not exceed the limit.
        $batchSize = 500
        for ($i = 0; $i -lt $membersOfRetrievedPermission.Count; $i += $batchSize) {
            $permission.AccountReferences = [array]($membersOfRetrievedPermission.GetRange($i, [Math]::Min($batchSize, $membersOfRetrievedPermission.Count - $i)))

            Write-Output $permission
        }
    }
    Write-Information 'Permission data import completed'
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-TriaswebError -ErrorObject $ex
        Write-Warning "Could not import Triasweb permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        Write-Warning "Could not import Triasweb permission. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}