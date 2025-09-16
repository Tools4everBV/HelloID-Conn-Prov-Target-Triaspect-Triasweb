#################################################
# HelloID-Conn-Prov-Target-Triaspect-Triasweb-Import
# PowerShell V2
#################################################

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
        Accept         = 'application/json'
    }

    $pageSize = 50
    $pageNumber = 1
    $importedAccounts = @()
    do {
        $splatGetUsers = @{
            Uri         = "$($actionContext.Configuration.BaseUrl)/api/users/list?pageNumber=$($pageNumber)&pageSize=$($pageSize)"
            Method      = 'Get'
            Certificate = $certificate
            Headers     = $headers
        }
        $response = Invoke-RestMethod @splatGetUsers

        if ($response.data) {
            $importedAccounts += $response.data
        }

        $pageNumber++
    } while ($pageNumber -le $response.totalPages)

    # Map the imported data to the account field mappings
    foreach ($importedAccount in $importedAccounts) {
        $data = $importedAccount

        # Enabled has a -not filter because the API uses an isDisabled property, which is the exact opposite of the enabled state used by HelloID.
        Write-Output @{
            AccountReference = $importedAccount.Id
            DisplayName      = $importedAccount.name
            UserName         = $importedAccount.Id
            Enabled          = -not($importedAccount.isDisabled)
            Data             = $data | Select-Object -Property * -ExcludeProperty managedOrganizationCodes, roleNames, authorizedOrganizationCodes
        }
    }
    Write-Information 'Account data import completed'
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-TriaswebError -ErrorObject $ex
        Write-Warning "Could not import Triasweb account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        Write-Warning "Could not import Triasweb account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}