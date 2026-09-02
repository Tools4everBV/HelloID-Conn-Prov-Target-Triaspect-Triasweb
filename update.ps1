#################################################
# HelloID-Conn-Prov-Target-Triaspect-Triasweb-Update
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
    # Verify if [aRef] has a value
    $actionMessage = 'checking account reference'
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

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
        Accept         = 'application/json'
    }

    $actionMessage = 'retrieving account'
    $splatGetUser = @{
        Uri         = "$($actionContext.Configuration.BaseUrl)/api/users?method=id&value=$($actionContext.References.Account)"
        Method      = 'Get'
        Certificate = $certificate
        Headers     = $headers
    }
    try {
        $correlatedAccount = (Invoke-RestMethod @splatGetUser).data
    }
    catch {
        if (-not($_.Exception.Response.StatusCode -eq 404)) {
            throw $_
        }
    }

    $actionMessage = 'calculating actions'
    if ($null -ne $correlatedAccount) {
        $correlatedAccount.authorizedOrganizationCodes = @($correlatedAccount.authorizedOrganizationCodes | Where-Object { ($_ -ne $null) -and ($_ -notmatch ',') })
        $outputContext.PreviousData = ($correlatedAccount | Select-Object -Property $outputContext.data.PSObject.Properties.Name -ExcludeProperty 'roleNames', 'authorizedOrganizationCodes')

        $actionContext.Data.roleNames = $correlatedAccount.roleNames
        $actionContext.Data.authorizedOrganizationCodes = $correlatedAccount.authorizedOrganizationCodes

        $actionMessage = 'calculating account changes'
        $splatCompareProperties = @{
            ReferenceObject  = @($correlatedAccount.PSObject.Properties)
            DifferenceObject = @($actionContext.Data.PSObject.Properties)
        }
        $propertiesChanged = Compare-Object @splatCompareProperties -PassThru | Where-Object { $_.SideIndicator -eq '=>' }

        if ($propertiesChanged) {
            $action = 'UpdateAccount'
        }
        else {
            $action = 'NoChanges'
        }
    }
    else {
        $action = 'NotFound'
    }

    Write-Information "Action to be executed: $($action)"

    # Process
    switch ($action) {
        'UpdateAccount' {
            $actionMessage = 'updating account'
            Write-Information "Account property(s) required to update: $($propertiesChanged.Name -join ', ')"

            $splatUpdateParams = @{
                Uri         = "$($actionContext.Configuration.BaseUrl)/api/users?method=id&value=$($actionContext.References.Account)"
                Method      = 'PUT'
                Certificate = $certificate
                Headers     = $headers
                Body        = ([System.Text.Encoding]::UTF8.GetBytes(($actionContext.Data | ConvertTo-Json -Depth 10)))
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Updating Triasweb account with accountReference: [$($actionContext.References.Account)]"
                $updatedAccount = (Invoke-RestMethod @splatUpdateParams).data
                $outputContext.Data = ($updatedAccount | Select-Object -Property $outputContext.data.PSObject.Properties.Name -ExcludeProperty 'roleNames', 'authorizedOrganizationCodes')
            }
            else {
                Write-Information "[DryRun] Update Triasweb account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Update account was successful, Account property(s) updated: [$($propertiesChanged.name -join ', ')]"
                    IsError = $false
                })
            break
        }

        'NoChanges' {
            $actionMessage = 'no changes to account'
            Write-Information "No changes to Triasweb account with accountReference: [$($actionContext.References.Account)]"
            $outputContext.Data = ($correlatedAccount | Select-Object -Property $outputContext.data.PSObject.Properties.Name -ExcludeProperty 'roleNames', 'authorizedOrganizationCodes')
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = 'No changes will be made to the account during enforcement'
                    IsError = $false
                })
            break
        }

        'NotFound' {
            $actionMessage = 'account not found'
            Write-Information "Triasweb account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            $outputContext.Success = $false
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Triasweb account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
                    IsError = $true
                })
            break
        }
    }
}
catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-TriaswebError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
