################################################################
# HelloID-Conn-Prov-Target-Triaspect-Triasweb-Permissions-Roles-Import
# PowerShell V2
################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

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
    if ($actionContext.Configuration.UseBase64Certificate -eq $true) {
        $actionMessage = 'retrieving certificate from base64 string'
        $rawCertificate = [system.convert]::FromBase64String($actionContext.Configuration.CertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $actionContext.Configuration.CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    }
    else {
        $actionMessage = 'retrieving certificate from pfx file'
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($actionContext.Configuration.CertificatePath, $actionContext.Configuration.CertificatePassword, 'UserKeySet')
    }
    
    $actionMessage = 'validating certificate date'
    if ($certificate.NotAfter -le (Get-Date)) {
        throw "Certificate has expired on $($certificate.NotAfter)..."
    }

    $actionMessage = 'retrieving access token'
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
    $importedPermissions = @{}
    do {
        $actionMessage = "retrieving permission import page [$pageNumber]"
        $splatGetUsers = @{
            Uri         = "$($actionContext.Configuration.BaseUrl)/api/users/list?pageNumber=$($pageNumber)&pageSize=$($pageSize)"
            Method      = 'GET'
            Certificate = $certificate
            Headers     = $headers
        }
        $response = Invoke-RestMethod @splatGetUsers

        if ($response.data) {
            foreach ($importedAccount in $response.data) {
                foreach ($role in $importedAccount.roleNames) {
                    if (![string]::IsNullOrWhiteSpace($role)) {
                        if (-not $importedPermissions.ContainsKey($role)) {
                            $importedPermissions[$role] = @()
                        }
                        $importedPermissions[$role] += $importedAccount.id
                    }
                }
            }
        }
        $pageNumber++
    } while ($pageNumber -le $response.totalPages)

    foreach ($importedPermission in $importedPermissions.GetEnumerator()) {
        $actionMessage = "importing permission [$($importedPermission.Key)]"
        $permission = @{
            AccountReferences   = $importedPermission.Value
            PermissionReference = @{
                Reference = $importedPermission.Key
            }
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
        Write-Warning "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        Write-Warning "Error $($actionMessage). Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}