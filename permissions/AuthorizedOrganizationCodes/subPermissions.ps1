################################################################
# HelloID-Conn-Prov-Target-Triaspect-Triasweb-SubPermissions-Authorization-Organization-Codes
# PowerShell V2
################################################################
# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Script Mapping lookup values
# Lookup values which are used in the mapping to determine the authorizationOrganizationCode
$authorizationOrganizationCodesLookupKey = { $_.CostCenter.code } # Mandatory
$authorizationOrganizationNameLookupKey = { $_.CostCenter.name } # Mandatory

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
    }

    Write-Information 'Verifying if a Triasweb account exists'
    $splatGetUser = @{
        Uri         = "$($actionContext.Configuration.BaseUrl)/api/users?method=id&value=$($actionContext.References.Account)"
        Method      = 'GET'
        Certificate = $certificate
        Headers     = $headers
    }
    try {
        $correlatedAccount = (Invoke-RestMethod @splatGetUser).data
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            $correlatedAccount = $null
        }
        else {
            throw $_
        }
    }

    $desiredPermissions = @()
    $desiredPermissionsExportList = @{}
    if (-Not($actionContext.Operation -eq "revoke")) {
        foreach ($contract in $personContext.Person.Contracts) {
            Write-Information "Contract: $($contract.ExternalId). In condition: $($contract.Context.InConditions)"
            if ($contract.Context.InConditions -OR ($actionContext.DryRun -eq $true)) {
                $desiredPermissions += ($contract | Select-Object $authorizationOrganizationCodesLookupKey).$authorizationOrganizationCodesLookupKey
                $desiredPermissionsExportList["$(($contract | Select-Object $authorizationOrganizationCodesLookupKey).$authorizationOrganizationCodesLookupKey)"] = $($contract | Select-Object $authorizationOrganizationNameLookupKey).$authorizationOrganizationNameLookupKey
            }
        }
    }

    if ($actionContext.Operation -match "update|grant" -AND $desiredPermissions.count -eq 0) {
        throw "Error no desire permissions found. Make sure [$authorizationOrganizationCodesLookupKey] is filled on all contracts"
    }

    $currentPermissions = $actionContext.CurrentPermissions.Reference.Id
    $desiredPermissions = $desiredPermissions | Sort-Object -Unique
    $currentPermissions = $currentPermissions | Sort-Object -Unique    
    Write-Information ("Desired Permissions: {0}" -f ($desiredPermissions | ConvertTo-Json))
    Write-Information ("Current Permissions: {0}" -f ($currentPermissions | ConvertTo-Json))

    if ((-Not([string]::IsNullOrEmpty($desiredPermissions))) -and (-Not([string]::IsNullOrEmpty($currentPermissions)))) {
        $splatCompareAuthorizedOrganizationCodes = @{
            ReferenceObject  = $desiredPermissions
            DifferenceObject = $currentPermissions
        }
        $authorizedOrganizationCodesChanged = Compare-Object @splatCompareAuthorizedOrganizationCodes
    }
    else {
        $authorizedOrganizationCodesChanged = $true
    }

    if ([string]::IsNullOrEmpty($correlatedAccount)) {
        $action = 'NotFound'
    }
    elseif ($authorizedOrganizationCodesChanged) {
        $action = 'UpdateAccount'
    }
    else {
        $action = 'NoChanges'
    }

    # Process
    switch ($action) {
        'UpdateAccount' {
            Write-Information "Account property authorizedOrganizationCodes required to update, new value(s) will be: $($desiredPermissions -join ', ')."
            $correlatedAccount.authorizedOrganizationCodes = @($desiredPermissions)

            $splatUpdateParams = @{
                Uri         = "$($actionContext.Configuration.BaseUrl)/api/users?method=id&value=$($actionContext.References.Account)"
                Method      = 'PUT'
                Certificate = $certificate
                Headers     = $headers
                Body        = ([System.Text.Encoding]::UTF8.GetBytes(($correlatedAccount | ConvertTo-Json -Depth 10)))
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Updating Triasweb account with accountReference: [$($actionContext.References.Account)]"
                $null = Invoke-RestMethod @splatUpdateParams
            }
            else {
                Write-Information "[DryRun] Update Triasweb account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{  
                    Message = "Update account was successful, New authorizedOrganizationCodes value(s) [$($desiredPermissions -join ', ')]"
                    IsError = $false
                })
            break
        }

        'NoChanges' {
            Write-Information "No changes to Triasweb account with accountReference: [$($actionContext.References.Account)]"
            $outputContext.Success = $true
            break
        }

        'NotFound' {
            Write-Information "Triasweb account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            if ($actionContext.Operation -eq "revoke") {
                $outputContext.Success = $true
            }
            else {
                $outputContext.Success = $false
            }
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Triasweb account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
                    IsError = $false
                })
            break
        }
    }

    $desiredPermissionsExportList = $desiredPermissionsExportList | Sort-Object Name -Unique
    foreach ($permission in $desiredPermissionsExportList.GetEnumerator()) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = "$($permission.Value) [$($permission.Name)]"
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })
    } 
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-TriaswebError -ErrorObject $ex
        $auditMessage = "Could not grant Triasweb permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not grant Triasweb permission. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}