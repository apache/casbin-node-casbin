<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Apache Casbin (Incubating) — Node-Casbin

Apache Casbin (Incubating) is an effort undergoing incubation at the Apache Software Foundation (ASF), sponsored by the Apache Incubator PMC.

Incubation is required of all newly accepted projects until a further review indicates that the infrastructure, communications, and decision making process have stabilized in a manner consistent with other successful ASF projects.

While incubation status is not necessarily a reflection of the completeness or stability of the code, it does indicate that the project has yet to be fully endorsed by the ASF.

Earlier package publications form the legacy Casbin community release history. Their presence in a registry does not establish Apache release approval. Apache releases require project and Incubator approval of the exact source distribution.


[![GitHub Actions](https://github.com/apache/casbin-node-casbin/workflows/main/badge.svg)](https://github.com/apache/casbin-node-casbin/actions)
[![Coverage Status](https://codecov.io/gh/apache/casbin-node-casbin/branch/master/graph/badge.svg)](https://codecov.io/gh/apache/casbin-node-casbin)
[![Release](https://img.shields.io/github/release/apache/casbin-node-casbin.svg)](https://github.com/apache/casbin-node-casbin/releases/latest)
[![NPM version][npm-image]][npm-url]
[![NPM download][download-image]][download-url]
[![install size](https://packagephobia.now.sh/badge?p=apache-casbin)](https://packagephobia.now.sh/result?p=apache-casbin)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

[npm-image]: https://img.shields.io/npm/v/apache-casbin.svg?style=flat-square
[npm-url]: https://npmjs.org/package/apache-casbin
[download-image]: https://img.shields.io/npm/dm/apache-casbin.svg?style=flat-square
[download-url]: https://npmjs.org/package/apache-casbin

**News**: still worry about how to write the correct `node-casbin` policy? [Casbin online editor](https://casbin.apache.org/editor) is coming to help!

![casbin Logo](casbin-logo.png)

`node-casbin` is a powerful and efficient open-source access control library for Node.JS projects. It provides support for enforcing authorization based on various [access control models](https://wikipedia.org/wiki/Computer_security_model).

## All the languages supported by Casbin:

| [![golang](https://casbin.apache.org/img/langs/golang.png)](https://github.com/casbin/casbin) | [![java](https://casbin.apache.org/img/langs/java.png)](https://github.com/casbin/jcasbin) | [![nodejs](https://casbin.apache.org/img/langs/nodejs.png)](https://github.com/apache/casbin-node-casbin) | [![php](https://casbin.apache.org/img/langs/php.png)](https://github.com/php-casbin/php-casbin) |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| [Casbin](https://github.com/casbin/casbin)                                                    | [jCasbin](https://github.com/casbin/jcasbin)                                               | [node-Casbin](https://github.com/apache/casbin-node-casbin)                                               | [PHP-Casbin](https://github.com/php-casbin/php-casbin)                                          |
| production-ready                                                                              | production-ready                                                                           | production-ready                                                                                          | production-ready                                                                                |

| [![python](https://casbin.apache.org/img/langs/python.png)](https://github.com/casbin/pycasbin) | [![dotnet](https://casbin.apache.org/img/langs/dotnet.png)](https://github.com/casbin-net/Casbin.NET) | [![c++](https://casbin.apache.org/img/langs/cpp.png)](https://github.com/casbin/casbin-cpp) | [![rust](https://casbin.apache.org/img/langs/rust.png)](https://github.com/casbin/casbin-rs) |
| ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [PyCasbin](https://github.com/casbin/pycasbin)                                                  | [Casbin.NET](https://github.com/casbin-net/Casbin.NET)                                                | [Casbin-CPP](https://github.com/casbin/casbin-cpp)                                          | [Casbin-RS](https://github.com/casbin/casbin-rs)                                             |
| production-ready                                                                                | production-ready                                                                                      | beta-test                                                                                   | production-ready                                                                             |

## Documentation

https://casbin.apache.org/docs/overview

## Installation

```shell script
# NPM
npm install apache-casbin --save

# Yarn
yarn add apache-casbin
```

## Get started

New a `node-casbin` enforcer with a model file and a policy file, see [Model](#official-model) section for details:

```node.js
// For Node.js:
const { newEnforcer } = require('apache-casbin');
// For browser:
// import { newEnforcer } from 'apache-casbin';

const enforcer = await newEnforcer('basic_model.conf', 'basic_policy.csv');
```

> **Note**: you can also initialize an enforcer with policy in DB instead of file, see [Persistence](#policy-persistence) section for details.

Add an enforcement hook into your code right before the access happens:

```node.js
const sub = 'alice'; // the user that wants to access a resource.
const obj = 'data1'; // the resource that is going to be accessed.
const act = 'read'; // the operation that the user performs on the resource.

// Async:
const res = await enforcer.enforce(sub, obj, act);
// Sync:
// const res = enforcer.enforceSync(sub, obj, act);

if (res) {
  // permit alice to read data1
} else {
  // deny the request, show an error
}
```

Besides the static policy file, `node-casbin` also provides API for permission management at run-time.
For example, You can get all the roles assigned to a user as below:

```node.js
const roles = await enforcer.getRolesForUser('alice');
```

See [Policy management APIs](#policy-management) for more usage.

## Policy management

Casbin provides two sets of APIs to manage permissions:

- [Management API](https://casbin.apache.org/docs/management-api): the primitive API that provides full support for Casbin policy management.
- [RBAC API](https://casbin.apache.org/docs/rbac-api): a more friendly API for RBAC. This API is a subset of Management API. The RBAC users could use this API to simplify the code.

## Official Model

https://casbin.apache.org/docs/supported-models

## Policy persistence

https://casbin.apache.org/docs/adapters

## Policy consistence between multiple nodes

https://casbin.apache.org/docs/watchers

## Role manager

https://casbin.apache.org/docs/role-managers

## Contributors

This project exists thanks to all the people who contribute.
<a href="https://github.com/apache/casbin-node-casbin/graphs/contributors"><img src="https://opencollective.com/node-casbin/contributors.svg?width=890&button=false" /></a>

## Star History

[![Star History Chart](https://star-history.dera.page/svg?repos=apache/casbin-node-casbin&type=Date)](https://star-history.dera.page/#apache/casbin-node-casbin&Date)

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PR is welcomed.

- https://github.com/apache/casbin-node-casbin/issues
- https://discord.gg/S5UjpzGZjN

## Runtime requirements

The runtime dependency supports Node.js 20 or 22 and later. Build and development tools require a current Node.js 20 LTS release or later.

## Package-name migration

The next approved distribution uses `apache-casbin` in place of the historical npm package `casbin`. The API is unchanged by the name migration. After the approved package is published, update dependency declarations and imports to `apache-casbin`, regenerate your lockfile and check that adapters use the same core package instance. Existing `casbin` releases remain available; updating that old dependency does not automatically switch packages. Do not install both core identities in one application. Candidates are for review, not installation from npm.
