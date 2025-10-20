# HelloID-Conn-Prov-Target-Triaspect-Triasweb

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://raw.githubusercontent.com/Tools4everBV/HelloID-Conn-Prov-Target-Triaspect-Triasweb/refs/heads/main/Logo.png">
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
    - [Account Reference](#account-reference)
  - [Remarks](#remarks)
    - [Concurrent sessions](#concurrent-sessions)
    - [On premises](#on-premises)
    - [Account lifecycle](#account-lifecycle)
    - [Permissions](#permissions)
      - [Roles](#roles)
      - [Permission list](#permission-list)
      - [AuthorizedOrganizationCodes](#authorizedorganizationcodes)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Triasweb_ is a _target_ connector. _Triasweb_ provides a set of REST API's that allow you to programmatically interact with its data. The connector creates, updates, enables, and disables users. It also assigns and revokes roles and authorizationOrganizationCodes for users.

## Supported  features

The following features are available:

| Feature                                   | Supported | Actions                                                         | Remarks                      |
| ----------------------------------------- | --------- | --------------------------------------------------------------- | ---------------------------- |
| **Account Lifecycle**                     | ✅         | Create, Update, Enable, Disable                                 | No Delete action             |
| **Permissions**                           | ✅         | Grant, Revoke (roles) and dynamic (authorizedOrganizationCodes) | Roles are Static Permissions |
| **Resources**                             | ❌         | -                                                               |                              |
| **Entitlement Import: Accounts**          | ✅         | -                                                               |                              |
| **Entitlement Import: Permissions**       | ✅         | -                                                               |                              |
| **Governance Reconciliation Resolutions** | ✅         | -                                                               | No Delete action             |

## Getting started

### Prerequisites

- **SSL Certificate**:<br>
  A valid SSL certificate must be installed on the server to ensure secure communication. The certificate should be trusted by a recognized Certificate Authority (CA) and must not be self-signed.

- **HR sync**:<br>
 The HR sync needs to be turned off, more information can be found at the HR sync off warning in the [Remarks](#remarks) below.

- **On premise HelloID Agent**:<br>
 A on premise HelloID is required, more information can be found at the HR sync off warning in the [Remarks](#remarks) below..

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
Besides the configuration and field mapping, you can also configure script variables for `permissions` `authorizationOrganizations` to decide which property from the HelloID contracts is used to look up a value in the mapping tables

#### Script Mapping lookup values
```Powershell
# Lookup values which are used in the mapping to determine the authorizationOrganizationCode
$authorizationOrganizationCodesLookupKey = { $_.CostCenter.code } # Mandatory
$authorizationOrganizationNameLookupKey = { $_.CostCenter.name } # Mandatory
```

### Account Reference
The account reference is populated with the property `id` property from _Triasweb_.

## Remarks

> [!WARNING]
> **HR sync off**: The Employee Sync (direct HR sync) must be disabled in _Triasweb_. Account and authorization management are handled by HelloID and the connector.

### Concurrent sessions
- **Concurrent sessions set to one**: Concurrent sessions should be set to one otherwise actions could interfere with each other.

### On premises
- **Certificate**: The API requires a certificate to be sent with the requests. Because of this, the connector can only function when running on-premises.

### Account lifecycle
- **Disable in create**: The create request always creates an enabled user. therefore, a disable request is included in the create lifecycle action.
- **No delete**: The API does not support a delete request for users; hence, there is no delete script
- **Unique email**: The email property in _Triasweb_ needs to be an unique value.

### Permissions
#### Roles
- **Default value**: The api requires the property `roleNames` to be included in the post request when creating a user. In the fieldmapping this property is mapped to an empty array so that _Triasweb_ can automatically grant the default role. This can later be changed through the permissions.
- **Static permissions**: In HelloID, role permissions are defined using a static list. This list can be different for each implementation, because roles can be added and modified in _Triasweb_. The permissions should be copied exactly as is (case-sensitive) Otherwise you will get a warning with Reconciliation. More information about how to create a static permission list please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/permissions/configure-a-permission-set.html)

#### Permission list
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
- **Import permissions**: Since there is no dedicated API call for importing roles, this is done based on the getPersons response and the role names it contains.

#### AuthorizedOrganizationCodes

- **Default value**: The api requires the property `authorizedOrganizationCodes` to be included in the post request when creating a user. In the fieldmapping this property is mapped to an empty array. This can later be changed through the permissions.
- **Dynamic permissions**: The `authorizedOrganizationCodes` can be dynamically synced to _Triasweb_ based on the conditions defined in the business rules. The value is stored as a sub-permission and is used in all future actions to determine whether an update is required.
- **Grant and Revoke**: To grant and revoke `authorizedOrganizationCodes` for a user, the user update API request is used.
- **Import permissions**: Since there is no dedicated API call for importing `authorizedOrganizationCodes`, this is done based on the getPersons response and the role names it contains.
- **Null value**: `AuthorizationOrganizationCodes` can contain a *null* value when no *sync value* is configured in the OE settings of _Triasweb_. These values must be filtered out before processing the property to avoid errors.  
- **Comma-separated value**: `AuthorizationOrganizationCodes` can contain multiple values that are returned as a single comma-separated string. _Triasweb_ does not correctly recognize this. These values must also be filtered out before processing the property to avoid errors.  

### API endpoints

The following endpoints are used by the connector

| Display Name          | Reference                                                     |
| --------------------- | ------------------------------------------------------------- |
| /connect/token        | Retrieve access token to connect to the API                   |
| /Users                | Retrieve user information, create and update user information |
| /Users/list           | Retrieve user information paginated                           |
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
