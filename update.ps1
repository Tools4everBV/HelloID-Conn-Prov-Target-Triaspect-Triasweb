#################################################
# HelloID-Conn-Prov-Target-Triaspect-Triasweb-Update
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Script Mapping lookup values
# Lookup values which are used in the mapping to determine the authorizationOrganizationCodes
$authorizationOrganizationCodesLookupKey = { $_.CostCenter.code } # Mandatory

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
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
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
            } elseif ($null -ne $errorDetailsObject.error) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error
            } else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        } catch {
            $httpErrorObj.FriendlyMessage = "Error: [$($httpErrorObj.ErrorDetails)] [$($_.Exception.Message)]"
        }
        Write-Output $httpErrorObj
    }
}
#endregion

try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

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

    Write-Information 'Verifying if a Triasweb account exists'
    $splatGetUser = @{
        Uri         = "$($actionContext.Configuration.BaseUrl)/api/users?method=id&value=$($actionContext.References.Account)"
        Method      = 'Get'
        Certificate = $certificate
        Headers     = $headers
    }
    try {
        $correlatedAccount = (Invoke-RestMethod @splatGetUser).data
    } catch {
        if (-not($_.Exception.Response.StatusCode -eq 404)) {
            throw $_
        }
    }

    if ($null -ne $correlatedAccount) {
        $correlatedAccount.authorizedOrganizationCodes = @($correlatedAccount.authorizedOrganizationCodes | Where-Object { $_ -ne $null })
        $outputContext.PreviousData = ($correlatedAccount | Select-Object -Property $actionContext.data.PSObject.Properties.Name)

        # Desired contract calculation (Also with preview modes)
        [array]$desiredContracts = $personContext.person.contracts | Where-Object { $_.Context.InConditions -eq $true }
        if ($actionContext.DryRun -eq $true) { [array]$desiredContracts = $personContext.person.contracts }
        if ($desiredContracts.length -lt 1) { throw 'No Contracts in scope [InConditions] found!' }

        # Populate empty arrays from actionContext with correct value's
        $actionContext.Data.authorizedOrganizationCodes += @(($desiredContracts | Select-Object $authorizationOrganizationCodesLookupKey).$authorizationOrganizationCodesLookupKey | Get-Unique)
        $actionContext.Data.roleNames = $correlatedAccount.roleNames

        # Populate outputContext.Data with actionContext.Data to prevent misleading audit logs in HelloID
        $outputContext.Data = $actionContext.Data

        $splatCompareProperties = @{
            ReferenceObject  = @($correlatedAccount.PSObject.Properties)
            DifferenceObject = @(($actionContext.Data | Select-Object -Property * -ExcludeProperty authorizedOrganizationCodes).PSObject.Properties)
        }
        $propertiesChanged = Compare-Object @splatCompareProperties -PassThru | Where-Object { $_.SideIndicator -eq '=>' }

        if ($correlatedAccount.authorizedOrganizationCodes.count -gt 0) {
            $splatCompareAuthorizedOrganizationCodes = @{
                ReferenceObject  = ($correlatedAccount.authorizedOrganizationCodes | Where-Object { $_ -ne $null })
                DifferenceObject = ($actionContext.Data.authorizedOrganizationCodes | Where-Object { $_ -ne $null })
            }
            $authorizedOrganizationCodesChanged = Compare-Object @splatCompareAuthorizedOrganizationCodes -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        } elseif ($actionContext.Data.authorizedOrganizationCodes.count -gt 0) {
            $authorizedOrganizationCodesChanged = $actionContext.Data.authorizedOrganizationCodes
        }

        if ($propertiesChanged -or $authorizedOrganizationCodesChanged) {
            $action = 'UpdateAccount'
        } else {
            $action = 'NoChanges'
        }
    } else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'UpdateAccount' {
            Write-Information "Account property(s) required to update: $($propertiesChanged.Name -join ', ')"

            if ($authorizedOrganizationCodesChanged) {
                Write-Information "Account property authorizedOrganizationCodes required to update, new value will be: $($actionContext.Data.authorizedOrganizationCodes -join ', ')"
            }

            $splatUpdateParams = @{
                Uri         = "$($actionContext.Configuration.BaseUrl)/api/users?method=id&value=$($actionContext.References.Account)"
                Method      = 'PUT'
                Certificate = $certificate
                Headers     = $headers
                Body        = ([System.Text.Encoding]::UTF8.GetBytes(($actionContext.Data | ConvertTo-Json -Depth 10)))
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Updating Triasweb account with accountReference: [$($actionContext.References.Account)]"
                $null = Invoke-RestMethod @splatUpdateParams
            } else {
                Write-Information "[DryRun] Update Triasweb account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Update account was successful, Account property(s) updated: [$($propertiesChanged.name -join ', ')]"
                    IsError = $false
                })

            if ($authorizedOrganizationCodesChanged) {
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Update account was successful, New authorizedOrganizationCodes value [$($actionContext.Data.authorizedOrganizationCodes -join ', ')]"
                        IsError = $false
                    })
            }
            break
        }

        'NoChanges' {
            Write-Information "No changes to Triasweb account with accountReference: [$($actionContext.References.Account)]"
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = 'No changes will be made to the account during enforcement'
                    IsError = $false
                })
            break
        }

        'NotFound' {
            Write-Information "Triasweb account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            $outputContext.Success = $false
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Triasweb account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
                    IsError = $true
                })
            break
        }
    }
} catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-TriaswebError -ErrorObject $ex
        $auditMessage = "Could not update Triasweb account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not update Triasweb account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
