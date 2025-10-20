################################################################
# HelloID-Conn-Prov-Target-Triaspect-Triasweb-Permissions-Roles-Revoke
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

# Begin
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

    if ($null -ne $correlatedAccount) {
        $action = 'RevokePermission'
    }
    else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'RevokePermission' {
            if ($correlatedAccount.roleNames -contains $actionContext.References.Permission.Reference) {
                $correlatedAccount.roleNames = @($correlatedAccount.roleNames | Where-Object { $_ -ne $actionContext.References.Permission.Reference })
                $correlatedAccount.authorizedOrganizationCodes = @($correlatedAccount.authorizedOrganizationCodes | Where-Object { ($_ -ne $null) -and ($_ -notmatch ',') })

                $splatRevokeParams = @{
                    Uri         = "$($actionContext.Configuration.BaseUrl)/api/users?method=id&value=$($actionContext.References.Account)"
                    Method      = 'PUT'
                    Certificate = $certificate
                    Headers     = $headers
                    Body        = ([System.Text.Encoding]::UTF8.GetBytes(($correlatedAccount | ConvertTo-Json -Depth 10)))
                }

                if (-not($actionContext.DryRun -eq $true)) {
                    Write-Information "Revoking Triasweb permission: [$($actionContext.References.Permission.Reference)]"
                    $null = Invoke-RestMethod @splatRevokeParams
                }
                else {
                    Write-Information "[DryRun] Revoke Triasweb permission: [$($actionContext.References.Permission.Reference)], will be executed during enforcement"
                }

                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Revoke permission [$($actionContext.References.Permission.Reference)] was successful"
                        IsError = $false
                    })
            }
            else {
                Write-Information "Triasweb permission: [$($actionContext.References.Permission.Reference)] could not be found, indicating that it may have been revoked"

                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Triasweb permission: [$($actionContext.References.Permission.Reference)] could not be found, indicating that it may have been revoked"
                        IsError = $false
                    })
            }
        }

        'NotFound' {
            Write-Information "Triasweb account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Triasweb account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
                    IsError = $false
                })
            break
        }
    }
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-TriaswebError -ErrorObject $ex
        $auditMessage = "Could not revoke Triasweb permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not revoke Triasweb permission. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}