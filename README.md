# HelloID-Conn-Prov-Target-Triaspect-Triasweb

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

> [!IMPORTANT]
> The connector is developed and tested in a test environment that has no authorization scope. As a result, the authorizedOrganizationCodes property will always return `null` when retrieving a user. Because of this, there are multiple places in the connector code that filter out these `null` values. If your environment does return valid authorization codes, you can remove these filters.

<p align="center">
  <img src="">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Triaspect-Triasweb](#helloid-conn-prov-target-triaspect-triasweb)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported  features](#supported--features)
  - [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
    - [Script Mapping](#script-mapping)
      - [Script Mapping lookup values](#script-mapping-lookup-values)
      - [authorizedOrganizationCodes Configuration](#authorizedorganizationcodes-configuration)
    - [Account Reference](#account-reference)
  - [Remarks](#remarks)
    - [Concurrent sessions](#concurrent-sessions)
    - [On premises](#on-premises)
    - [Account lifecycle](#account-lifecycle)
    - [AuthorizationOrganizationCodes](#authorizationorganizationcodes)
    - [permissions](#permissions)
      - [permission list](#permission-list)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Triasweb_ is a _target_ connector. _Triasweb_ provides a set of REST API's that allow you to programmatically interact with its data. The connector creates, updates, enables, and disables users. It also assigns and revokes roles and authorizationOrganizationCodes for users.

## Supported  features

The following features are available:

| Feature                                   | Supported | Actions                         | Remarks            |
| ----------------------------------------- | --------- | ------------------------------- | ------------------ |
| **Account Lifecycle**                     | ✅         | Create, Update, Enable, Disable | No Delete action   |
| **Permissions**                           | ✅         | Grant, Revoke                   | Static Permissions |
| **Resources**                             | ❌         | -                               |                    |
| **Entitlement Import: Accounts**          | ✅         | -                               |                    |
| **Entitlement Import: Permissions**       | ✅         | -                               |                    |
| **Governance Reconciliation Resolutions** | ✅         | -                               | No Delete action   |

## Getting started

### Prerequisites

- **SSL Certificate**:<br>
  A valid SSL certificate must be installed on the server to ensure secure communication. The certificate should be trusted by a recognized Certificate Authority (CA) and must not be self-signed.

- **HR sync**:<br>
 The HR sync needs to be turned off, more information can be found at the HR sync off warning in the [Remarks](#remarks) below.
  

### Connection settings

The following settings are required to connect to the API.

| Setting              | Description                        | Mandatory |
| -------------------- | ---------------------------------- | --------- |
| ClientId             | The UserName to connect to the API | Yes       |
| ClientSecret         | The Password to connect to the API | Yes       |
| BaseUrl              | The URL to the API                 | Yes       |
| TokenBaseUrl         | The URL to retrieve the API token  | Yes       |
| Certificate path     | The full path to .PFX file         | Yes       |
| Certificate password | The Password of the .PFX file      | Yes       |


### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _Triasweb_ to a person in _HelloID_.

| Setting                   | Value                             |
| ------------------------- | --------------------------------- |
| Enable correlation        | `True`                            |
| Person correlation field  | `PersonContext.Person.ExternalId` |
| Account correlation field | `Reference`                       |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

### Script Mapping
Besides the configuration and field mapping, you can also configure script variables to decide which property from the HelloID contracts is used to look up a value in the mapping tables. Please note that the `same` configuration must be applied in both the create and update scripts, as shown below:

#### Script Mapping lookup values
```Powershell
# Lookup values which are used in the mapping to determine the authorizationOrganizationCodes
$authorizationOrganizationCodesLookupKey = { $_.CostCenter.code } # Mandatory
```

#### authorizedOrganizationCodes Configuration
```Powershell
# Retrieve all unique authorizationOrganizationCodes from contracts in condition based on the lookupKey.
[array]$desiredContracts = $personContext.person.contracts | Where-Object { $_.Context.InConditions -eq $true }
if ($actionContext.DryRun -eq $true) { [array]$desiredContracts = $personContext.person.contracts }
if ($desiredContracts.length -lt 1) { throw 'No Contracts in scope [InConditions] found!' }

$actionContext.Data.authorizedOrganizationCodes += @(($desiredContracts | Select-Object $authorizationOrganizationCodesLookupKey).$authorizationOrganizationCodesLookupKey | Get-Unique)
```

### Account Reference

The account reference is populated with the property `id` property from _Triasweb_

## Remarks

> [!WARNING]
> **HR sync off**: The Employee Sync (direct HR sync) must be disabled in Triasweb. Account and authorization management are handled by HelloID and the connector.

### Concurrent sessions
- **Concurrent sessions set to one**: Concurrent sessions should be set to one otherwise actions could interfere with each other.

### On premises
- **Certificate**: The API requires a certificate to be sent with the requests. Because of this, the connector can only function when running on-premises.

### Account lifecycle
- **Disable in create**: The create request always creates an enabled user. therefore, a disable request is included in the create lifecycle action.
- **No delete**: The API does not support a delete request for users; hence, there is no delete script
- **Unique email**: The email property in Triasweb needs to be an unique value.

### AuthorizationOrganizationCodes
- **AuthorizationOrganizationCodes in account lifecycle**: AuthorizationOrganizationCodes are handled through the create and update actions of the account lifecycle. Therefore, there is no permission definition and no import script for authorizationOrganizationCodes.
- **Existing authorizationOrganizationCodes**: AuthorizationOrganizationCodes send via the api requests need to exist in Triasweb, otherwise the request will return an error.
- **Null value**: AuthorizationOrganizationCodes often contains a null value in the array, which we need to filter out before processing the property to avoid errors.
-  **Extra compare**: To compare the authorizationOrganizationCodes array, a separate comparison is performed in the update script.

### permissions
- **default value**: The api requires the property `roleNames` to be included in the post request when creating a user. In the fieldmapping this property is mapped to an empty array so that Triasweb can automatically grant the default role. This can later be changed through the permissions.
- **Static permissions**: In HelloID, role permissions are defined using a static list. This list can be different for each implementation, because roles can be added and modified in Triasweb. The permissions should be copied exactly as is (case-sensitive) Otherwise you will get a warning with Reconciliation. More information about how to create a static permission list please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/permissions/configure-a-permission-set.html)

#### permission list
| Display name                 | Reference                    |
| ---------------------------- | ---------------------------- |
| Melder                       | Melder                       |
| Projectgroeplid              | Projectgroeplid              |
| Test                         | Test                         |
| Applicatiebeheer             | Applicatiebeheer             |
| Analist                      | Analist                      |
| Analist (inzage betrokkenen) | Analist (inzage betrokkenen) |
| Analist (beperkt recht)      | Analist (beperkt recht)      |
| Afhandelaar                  | Afhandelaar                  |


- **Grant and Revoke**: To grant and revoke roles for a user, the user update API request is used.
- **Import permissions**: Since there is no dedicated API call for importing permissions, this is done based on the getPersons response and the role names it contains.

### API endpoints

The following endpoints are used by the connector

| Display Name          | Reference                                                     |
| --------------------- | ------------------------------------------------------------- |
| /connect/token        | Retrieve access token to connect to the API                   |
| /Users                | Retrieve user information, create and update user information |
| /Users/list           | Retrieve user informaiton paginated                           |
| /Users/reopen-account | Enable user                                                   |
| /Users/close-account  | Disable user                                                  |

### API documentation
[Documentation](https://docs.triasweb.nl/TRIAS/api)

[Swagger](https://swaggerapi-test.triasweb.nl/triaswebapi/index.html)

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/provisioning/5376-helloid-conn-prov-target-triaspect-triasweb)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
