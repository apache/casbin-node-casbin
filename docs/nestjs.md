# Using Casbin with NestJS

This guide demonstrates how to integrate Casbin with a NestJS application using a custom guard for authorization.

## Installation

Install Casbin in your NestJS project:

```bash
npm install casbin
```

# Create a Casbin Guard

Create a guard to handle authorization using Casbin.
```bash
import {
  Injectable,
  CanActivate,
  ExecutionContext,
} from '@nestjs/common';
import { newEnforcer } from 'casbin';

@Injectable()
export class CasbinGuard implements CanActivate {
  private enforcer: any;

  async onModuleInit() {
    this.enforcer = await newEnforcer(
      'basic_model.conf',
      'basic_policy.csv'
    );
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    const user = 'alice'; // example user
    const resource = request.url;
    const action = request.method;

    return await this.enforcer.enforce(user, resource, action);
  }
}
```

# Use Guard in Controller

Apply the guard to protect routes.
```bash
import { Controller, Get, UseGuards } from '@nestjs/common';
import { CasbinGuard } from './casbin.guard';

@Controller()
export class AppController {

  @UseGuards(CasbinGuard)
  @Get('data')
  getData() {
    return 'Protected Data';
  }
}
```

# Model Configuration

Create a file named basic_model.conf:

```bash
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

# Policy Example

Create a file named basic_policy.csv:

```bash
p, alice, /data, GET
```

# How It Works
- Casbin loads the model and policy.
- NestJS guard intercepts incoming requests.
- The enforce function checks permissions.
- If access is allowed, the request proceeds.
- If denied, the request is blocked.

# Example Result

When accessing:
```GET /data```
- User alice → Allowed
- Other users → Denied