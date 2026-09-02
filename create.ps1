#################################################
# HelloID-Conn-Prov-Target-Triaspect-Triasweb-Create
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
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'

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
        'content-type' = 'application/json-patch+json'
    }

    # Validate correlation configuration
    $actionMessage = 'validating correlation configuration'
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.AccountField
        $correlationValue = $actionContext.CorrelationConfiguration.PersonFieldValue

        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
        }

        $actionMessage = "correlating account on field: [$correlationField] with value: [$correlationValue]"
        $splatGetUser = @{
            Uri         = "$($actionContext.Configuration.BaseUrl)/api/users?method=$($correlationField)&value=$($correlationValue)"
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
    }

    $actionMessage = 'calculating actions'
    if (($correlatedAccount | Measure-Object).count -eq 0) {
        $action = 'CreateAccount'
    }
    elseif (($correlatedAccount | Measure-Object).count -eq 1) {
        $action = 'CorrelateAccount'
    }
    elseif (($correlatedAccount | Measure-Object).count -gt 1) {
        throw "Multiple accounts found for person where $correlationField is: [$correlationValue]"
    }

    Write-Information "Action to be executed: $($action)"

    # Process
    switch ($action) {
        'CreateAccount' {
            $actionMessage = 'creating account'
            $splatCreateParams = @{
                Uri         = "$($actionContext.Configuration.BaseUrl)/api/users"
                Method      = 'POST'
                Certificate = $certificate
                Headers     = $headers
                Body        = ([System.Text.Encoding]::UTF8.GetBytes(($actionContext.Data | ConvertTo-Json -Depth 10)))
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information 'Creating, disabling and correlating Triasweb account'
                $createdAccount = (Invoke-RestMethod @splatCreateParams).data

                # Remove default $null value in authorizedOrganizationCodes
                $createdAccount.authorizedOrganizationCodes = @($createdAccount.authorizedOrganizationCodes | Where-Object { $_ -ne $null })

                $outputContext.Data = ($createdAccount | Select-Object -Property $outputContext.Data.PSObject.Properties.Name -ExcludeProperty 'roleNames', 'authorizedOrganizationCodes')
                $outputContext.AccountReference = $createdAccount.Id
            }
            else {
                Write-Information '[DryRun] Create and correlate Triasweb account, will be executed during enforcement'
            }

            $actionMessage = 'disabling account after creating'
            $splatDisableUserParams = @{
                Uri         = "$($actionContext.Configuration.BaseUrl)/api/users/close-account?method=id&value=$($outputContext.AccountReference)"
                Method      = 'PUT'
                Certificate = $certificate
                Headers     = $headers
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information 'Creating and correlating Triasweb account'
                $null = Invoke-RestMethod @splatDisableUserParams
            }
            else {
                Write-Information '[DryRun] Disable Triasweb account, will be executed during enforcement'
            }

            $auditLogMessage = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)]"
            break
        }

        'CorrelateAccount' {
            $actionMessage = 'correlating account'

            # Remove default $null value in authorizedOrganizationCodes
            $correlatedAccount.authorizedOrganizationCodes = @($correlatedAccount.authorizedOrganizationCodes | Where-Object { $_ -ne $null })

            $outputContext.Data = ($correlatedAccount | Select-Object -Property $outputContext.data.PSObject.Properties.Name -ExcludeProperty 'roleNames', 'authorizedOrganizationCodes')
            $outputContext.AccountReference = $correlatedAccount.Id
            $outputContext.AccountCorrelated = $true
            $auditLogMessage = "Correlated account: [$($outputContext.AccountReference)] on field: [$($correlationField)] with value: [$($correlationValue)]"
            break
        }
    }

    $outputContext.success = $true
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Action  = $action
            Message = $auditLogMessage
            IsError = $false
        })
}
catch {
    $outputContext.success = $false
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