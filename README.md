# Node-Casbin

[![GitHub Actions](https://github.com/cooronx/casbin-node-casbin/workflows/main/badge.svg)](https://github.com/cooronx/casbin-node-casbin/actions)
[![Coverage Status](https://codecov.io/gh/cooronx/casbin-node-casbin/branch/master/graph/badge.svg)](https://codecov.io/gh/cooronx/casbin-node-casbin)
[![Release](https://img.shields.io/github/release/cooronx/casbin-node-casbin.svg)](https://github.com/cooronx/casbin-node-casbin/releases/latest)
[![NPM version][npm-image]][npm-url]
[![NPM download][download-image]][download-url]
[![install size](https://packagephobia.now.sh/badge?p=casbin)](https://packagephobia.now.sh/result?p=casbin)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

[npm-image]: https://img.shields.io/npm/v/casbin.svg?style=flat-square
[npm-url]: https://npmjs.org/package/casbin
[download-image]: https://img.shields.io/npm/dm/casbin.svg?style=flat-square
[download-url]: https://npmjs.org/package/casbin

**News**: still worry about how to write the correct `node-casbin` policy? [Casbin online editor](https://casbin.apache.org/editor) is coming to help!

![casbin Logo](casbin-logo.png)

`node-casbin` is a powerful and efficient open-source access control library for Node.JS projects. It provides support for enforcing authorization based on various [access control models](https://wikipedia.org/wiki/Computer_security_model).

## All the languages supported by Casbin:

| [![golang](https://casbin.apache.org/img/langs/golang.png)](https://github.com/casbin/casbin) | [![java](https://casbin.apache.org/img/langs/java.png)](https://github.com/casbin/jcasbin) | [![nodejs](https://casbin.apache.org/img/langs/nodejs.png)](https://github.com/cooronx/casbin-node-casbin) | [![php](https://casbin.apache.org/img/langs/php.png)](https://github.com/php-casbin/php-casbin) |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| [Casbin](https://github.com/casbin/casbin)                                                    | [jCasbin](https://github.com/casbin/jcasbin)                                               | [node-Casbin](https://github.com/cooronx/casbin-node-casbin)                                               | [PHP-Casbin](https://github.com/php-casbin/php-casbin)                                          |
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
npm install casbin --save

# Yarn
yarn add casbin
```

## Get started

New a `node-casbin` enforcer with a model file and a policy file, see [Model](#official-model) section for details:

```node.js
// For Node.js:
const { newEnforcer } = require('casbin');
// For browser:
// import { newEnforcer } from 'casbin';

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
<a href="https://github.com/cooronx/casbin-node-casbin/graphs/contributors"><img src="https://opencollective.com/node-casbin/contributors.svg?width=890&button=false" /></a>

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=cooronx/casbin-node-casbin&type=Date)](https://star-history.com/#cooronx/casbin-node-casbin&Date)

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PR is welcomed.

- https://github.com/cooronx/casbin-node-casbin/issues
- https://discord.gg/S5UjpzGZjN
