// Copyright 2018 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// noinspection JSMismatchedCollectionQueryUpdate

import { DefaultRoleManager, Enforcer, newEnforcer, newModel, StringAdapter } from '../src';
import { keyMatch2Func, keyMatch3Func, keyMatchFunc } from '../src/util';

async function testEnforce(e: Enforcer, sub: string, obj: any, act: string, res: boolean): Promise<void> {
  await expect(e.enforce(sub, obj, act)).resolves.toBe(res);
}

async function testEnforceWithoutUsers(e: Enforcer, obj: string, act: string, res: boolean): Promise<void> {
  await expect(e.enforce(obj, act)).resolves.toBe(res);
}

async function testDomainEnforce(e: Enforcer, sub: string, dom: string, obj: string, act: string, res: boolean): Promise<void> {
  await expect(e.enforce(sub, dom, obj, act)).resolves.toBe(res);
}

test('TestBasicModel', async () => {
  const e = await newEnforcer('examples/basic_model.conf', 'examples/basic_policy.csv');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestBasicModelNoPolicy', async () => {
  const e = await newEnforcer('examples/basic_model.conf');

  await testEnforce(e, 'alice', 'data1', 'read', false);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', false);
});

test('TestBasicModelWithRoot', async () => {
  const e = await newEnforcer('examples/basic_with_root_model.conf', 'examples/basic_policy.csv');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
  await testEnforce(e, 'root', 'data1', 'read', true);
  await testEnforce(e, 'root', 'data1', 'write', true);
  await testEnforce(e, 'root', 'data2', 'read', true);
  await testEnforce(e, 'root', 'data2', 'write', true);
});

test('TestBasicModelWithRootNoPolicy', async () => {
  const e = await newEnforcer('examples/basic_with_root_model.conf');

  await testEnforce(e, 'alice', 'data1', 'read', false);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', false);
  await testEnforce(e, 'root', 'data1', 'read', true);
  await testEnforce(e, 'root', 'data1', 'write', true);
  await testEnforce(e, 'root', 'data2', 'read', true);
  await testEnforce(e, 'root', 'data2', 'write', true);
});

test('TestBasicModelWithoutUsers', async () => {
  const e = await newEnforcer('examples/basic_without_users_model.conf', 'examples/basic_without_users_policy.csv');

  await testEnforceWithoutUsers(e, 'data1', 'read', true);
  await testEnforceWithoutUsers(e, 'data1', 'write', false);
  await testEnforceWithoutUsers(e, 'data2', 'read', false);
  await testEnforceWithoutUsers(e, 'data2', 'write', true);
});

test('TestBasicModelWithoutResources', async () => {
  const e = await newEnforcer('examples/basic_without_resources_model.conf', 'examples/basic_without_resources_policy.csv');

  await testEnforceWithoutUsers(e, 'alice', 'read', true);
  await testEnforceWithoutUsers(e, 'alice', 'write', false);
  await testEnforceWithoutUsers(e, 'bob', 'read', false);
  await testEnforceWithoutUsers(e, 'bob', 'write', true);
});

test('TestRBACModel', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_policy.csv');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', true);
  await testEnforce(e, 'alice', 'data2', 'write', true);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestRBACModelWithResourceRoles', async () => {
  const e = await newEnforcer('examples/rbac_with_resource_roles_model.conf', 'examples/rbac_with_resource_roles_policy.csv');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', true);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', true);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestRBACModelWithDomains', async () => {
  const e = await newEnforcer('examples/rbac_with_domains_model.conf', 'examples/rbac_with_domains_policy.csv');

  await testDomainEnforce(e, 'alice', 'domain1', 'data1', 'read', true);
  await testDomainEnforce(e, 'alice', 'domain1', 'data1', 'write', true);
  await testDomainEnforce(e, 'alice', 'domain1', 'data2', 'read', false);
  await testDomainEnforce(e, 'alice', 'domain1', 'data2', 'write', false);
  await testDomainEnforce(e, 'bob', 'domain2', 'data1', 'read', false);
  await testDomainEnforce(e, 'bob', 'domain2', 'data1', 'write', false);
  await testDomainEnforce(e, 'bob', 'domain2', 'data2', 'read', true);
  await testDomainEnforce(e, 'bob', 'domain2', 'data2', 'write', true);
});

class TestResource {
  public Name: string;
  public Owner: string;

  constructor(name: string, owner: string) {
    this.Name = name;
    this.Owner = owner;
  }
}

test('TestGlobMatchModel', async () => {
  const e = await newEnforcer('examples/glob_model.conf', 'examples/glob_policy.csv');

  await testEnforce(e, 'u1', '/foo', 'read', false);
  await testEnforce(e, 'u1', '/foo/subprefix', 'read', true);
  await testEnforce(e, 'u1', 'foo', 'read', false);

  await testEnforce(e, 'u2', '/foosubprefix', 'read', true);
  await testEnforce(e, 'u2', '/foo/subprefix', 'read', false);
  await testEnforce(e, 'u2', 'foo', 'read', false);

  await testEnforce(e, 'u3', '/prefix/foo/subprefix', 'read', true);
  await testEnforce(e, 'u3', '/prefix/foo', 'read', false);

  await testEnforce(e, 'u4', '/foo', 'read', false);
  await testEnforce(e, 'u4', 'foo', 'read', true);
});

test('TestABACModel', async () => {
  const e = await newEnforcer('examples/abac_model.conf');

  const data1 = new TestResource('data1', 'alice');
  const data2 = new TestResource('data2', 'bob');

  await testEnforce(e, 'alice', data1, 'read', true);
  await testEnforce(e, 'alice', data1, 'write', true);
  await testEnforce(e, 'alice', data2, 'read', false);
  await testEnforce(e, 'alice', data2, 'write', false);
  await testEnforce(e, 'bob', data1, 'read', false);
  await testEnforce(e, 'bob', data1, 'write', false);
  await testEnforce(e, 'bob', data2, 'read', true);
  await testEnforce(e, 'bob', data2, 'write', true);
});

test('TestABACNotUsingPolicy', async () => {
  const e = await newEnforcer('examples/abac_not_using_policy_model.conf', 'examples/abac_rule_effect_policy.csv');

  const data1 = new TestResource('data1', 'alice');
  const data2 = new TestResource('data2', 'bob');

  await testEnforce(e, 'alice', data1, 'read', true);
  await testEnforce(e, 'alice', data1, 'write', true);
  await testEnforce(e, 'alice', data2, 'read', false);
  await testEnforce(e, 'alice', data2, 'write', false);
});

test('TestKeyMatchModel', async () => {
  const e = await newEnforcer('examples/keymatch_model.conf', 'examples/keymatch_policy.csv');

  await testEnforce(e, 'alice', '/alice_data/resource1', 'GET', true);
  await testEnforce(e, 'alice', '/alice_data/resource1', 'POST', true);
  await testEnforce(e, 'alice', '/alice_data/resource2', 'GET', true);
  await testEnforce(e, 'alice', '/alice_data/resource2', 'POST', false);
  await testEnforce(e, 'alice', '/bob_data/resource1', 'GET', false);
  await testEnforce(e, 'alice', '/bob_data/resource1', 'POST', false);
  await testEnforce(e, 'alice', '/bob_data/resource2', 'GET', false);
  await testEnforce(e, 'alice', '/bob_data/resource2', 'POST', false);

  await testEnforce(e, 'bob', '/alice_data/resource1', 'GET', false);
  await testEnforce(e, 'bob', '/alice_data/resource1', 'POST', false);
  await testEnforce(e, 'bob', '/alice_data/resource2', 'GET', true);
  await testEnforce(e, 'bob', '/alice_data/resource2', 'POST', false);
  await testEnforce(e, 'bob', '/bob_data/resource1', 'GET', false);
  await testEnforce(e, 'bob', '/bob_data/resource1', 'POST', true);
  await testEnforce(e, 'bob', '/bob_data/resource2', 'GET', false);
  await testEnforce(e, 'bob', '/bob_data/resource2', 'POST', true);

  await testEnforce(e, 'cathy', '/cathy_data', 'GET', true);
  await testEnforce(e, 'cathy', '/cathy_data', 'POST', true);
  await testEnforce(e, 'cathy', '/cathy_data', 'DELETE', false);
});

test('TestKeyMatch2Model', async () => {
  const e = await newEnforcer('examples/keymatch2_model.conf', 'examples/keymatch2_policy.csv');

  await testEnforce(e, 'alice', '/alice_data', 'GET', false);
  await testEnforce(e, 'alice', '/alice_data/resource1', 'GET', true);
  await testEnforce(e, 'alice', '/alice_data2/myid', 'GET', false);
  await testEnforce(e, 'alice', '/alice_data2/myid/using/res_id', 'GET', true);
});

function customFunction(key1: string, key2: string): boolean {
  if (key1 === '/alice_data2/myid/using/res_id' && key2 === '/alice_data/:resource') {
    return true;
  } else if (key1 === '/alice_data2/myid/using/res_id' && key2 === '/alice_data2/:id/using/:resId') {
    return true;
  } else {
    return false;
  }
}

function customFunctionWrapper(...args: any[]): boolean {
  const name1 = String(args[0]);
  const name2 = String(args[1]);

  return customFunction(name1, name2);
}

test('TestKeyMatchCustomModel', async () => {
  const e = await newEnforcer('examples/keymatch_custom_model.conf', 'examples/keymatch2_policy.csv');

  e.addFunction('keyMatchCustom', customFunctionWrapper);

  await testEnforce(e, 'alice', '/alice_data2/myid', 'GET', false);
  await testEnforce(e, 'alice', '/alice_data2/myid/using/res_id', 'GET', true);
});

test('TestIPMatchModel', async () => {
  const e = await newEnforcer('examples/ipmatch_model.conf', 'examples/ipmatch_policy.csv');

  await testEnforce(e, '192.168.2.123', 'data1', 'read', true);
  await testEnforce(e, '192.168.2.123', 'data1', 'write', false);
  await testEnforce(e, '192.168.2.123', 'data2', 'read', false);
  await testEnforce(e, '192.168.2.123', 'data2', 'write', false);

  await testEnforce(e, '192.168.0.123', 'data1', 'read', false);
  await testEnforce(e, '192.168.0.123', 'data1', 'write', false);
  await testEnforce(e, '192.168.0.123', 'data2', 'read', false);
  await testEnforce(e, '192.168.0.123', 'data2', 'write', false);

  await testEnforce(e, '10.0.0.5', 'data1', 'read', false);
  await testEnforce(e, '10.0.0.5', 'data1', 'write', false);
  await testEnforce(e, '10.0.0.5', 'data2', 'read', false);
  await testEnforce(e, '10.0.0.5', 'data2', 'write', true);

  await testEnforce(e, '192.168.0.1', 'data1', 'read', false);
  await testEnforce(e, '192.168.0.1', 'data1', 'write', false);
  await testEnforce(e, '192.168.0.1', 'data2', 'read', false);
  await testEnforce(e, '192.168.0.1', 'data2', 'write', false);
});

test('TestPriorityModel', async () => {
  const e = await newEnforcer('examples/priority_model.conf', 'examples/priority_policy.csv');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', true);
  await testEnforce(e, 'bob', 'data2', 'write', false);
});

test('TestExplicitPriorityModel', async () => {
  const e = await newEnforcer('examples/priority_model_explicit.conf', 'examples/priority_policy_explicit.csv');

  await testEnforce(e, 'alice', 'data1', 'write', true);
  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
  await testEnforce(e, 'data1_deny_group', 'data1', 'read', false);
  await testEnforce(e, 'data1_deny_group', 'data1', 'write', false);
  await testEnforce(e, 'data2_allow_group', 'data2', 'read', true);
  await testEnforce(e, 'data2_allow_group', 'data2', 'write', true);
});

test('TestExplicitPriorityModelAddPolicy', async () => {
  const e = await newEnforcer('examples/priority_model_explicit.conf', 'examples/priority_policy_explicit.csv');

  await e.addPolicy('1', 'bob', 'data2', 'write', 'deny');

  await testEnforce(e, 'alice', 'data1', 'write', true);
  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', false);
  await testEnforce(e, 'data1_deny_group', 'data1', 'read', false);
  await testEnforce(e, 'data1_deny_group', 'data1', 'write', false);
  await testEnforce(e, 'data2_allow_group', 'data2', 'read', true);
  await testEnforce(e, 'data2_allow_group', 'data2', 'write', true);
});

test('TestExplicitPriorityModelUpdatePolicy', async () => {
  const e = await newEnforcer('examples/priority_model_explicit.conf', 'examples/priority_policy_explicit_update.csv');

  await e.updatePolicy(['1', 'bob', 'data2', 'write', 'allow'], ['1', 'bob', 'data2', 'write', 'deny']);

  await testEnforce(e, 'alice', 'data1', 'write', true);
  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', false);
  await testEnforce(e, 'data1_deny_group', 'data1', 'read', false);
  await testEnforce(e, 'data1_deny_group', 'data1', 'write', false);
  await testEnforce(e, 'data2_allow_group', 'data2', 'read', true);
  await testEnforce(e, 'data2_allow_group', 'data2', 'write', true);

  await expect(e.updatePolicy(['1', 'bob', 'data2', 'write', 'allow'], ['2999', 'bob', 'data2', 'write', 'deny'])).resolves.toBe(false);
});

test('TestPriorityModelIndeterminate', async () => {
  const e = await newEnforcer('examples/priority_model.conf', 'examples/priority_indeterminate_policy.csv');

  await testEnforce(e, 'alice', 'data1', 'read', false);
});

test('TestMatcher', async () => {
  const m = newModel();

  m.addDef('m', 'm', 'keyMatch(r.obj, ".*get$") || regexMatch(r.act, ".user.")');

  expect(m.model.get('m')?.get('m')?.value).toEqual(`keyMatch(r_obj, ".*get$") || regexMatch(r_act, ".user.")`);
});

test('TestRBACModelWithPattern', async () => {
  const e = await newEnforcer('examples/rbac_with_pattern_model.conf', 'examples/rbac_with_pattern_policy.csv');

  // Here's a little confusing: the matching function here is not the custom function used in matcher.
  // It is the matching function used by "g" (and "g2", "g3" if any..)
  // You can see in policy that: "g2, /book/:id, book_group", so in "g2()" function in the matcher, instead
  // of checking whether "/book/:id" equals the obj: "/book/1", it checks whether the pattern matches.
  // You can see it as normal RBAC: "/book/:id" == "/book/1" becomes KeyMatch2("/book/:id", "/book/1")
  await e.addNamedMatchingFunc('g2', keyMatch2Func);
  await testEnforce(e, 'alice', '/book/1', 'GET', true);
  await testEnforce(e, 'alice', '/book/2', 'GET', true);
  await testEnforce(e, 'alice', '/pen/1', 'GET', true);
  await testEnforce(e, 'alice', '/pen/2', 'GET', false);
  await testEnforce(e, 'bob', '/book/1', 'GET', false);
  await testEnforce(e, 'bob', '/book/2', 'GET', false);
  await testEnforce(e, 'bob', '/pen/1', 'GET', true);
  await testEnforce(e, 'bob', '/pen/2', 'GET', true);

  // AddMatchingFunc() is actually setting a function because only one function is allowed,
  // so when we set "KeyMatch3", we are actually replacing "KeyMatch2" with "KeyMatch3".
  // From v5.5.0, you can use addNamedMatchingFunc(), which resolve the problem above
  await e.addNamedMatchingFunc('g2', keyMatch3Func);
  await testEnforce(e, 'alice', '/book2/1', 'GET', true);
  await testEnforce(e, 'alice', '/book2/2', 'GET', true);
  await testEnforce(e, 'alice', '/pen2/1', 'GET', true);
  await testEnforce(e, 'alice', '/pen2/2', 'GET', false);
  await testEnforce(e, 'bob', '/book2/1', 'GET', false);
  await testEnforce(e, 'bob', '/book2/2', 'GET', false);
  await testEnforce(e, 'bob', '/pen2/1', 'GET', true);
  await testEnforce(e, 'bob', '/pen2/2', 'GET', true);
});

test('TestNodeCasbin150', async () => {
  const e = await newEnforcer('examples/issues/node_casbin_150_model.conf', 'examples/issues/node_casbin_150_policy.csv');

  const rm = e.getRoleManager() as DefaultRoleManager;
  await rm.addMatchingFunc(keyMatchFunc);
  await e.buildRoleLinks();

  await e.getImplicitRolesForUser('alice');
});

test('TestDomainMatchModel', async () => {
  const e = await newEnforcer('examples/rbac_with_domain_pattern_model.conf', 'examples/rbac_with_domain_pattern_policy.csv');

  const rm = e.getRoleManager() as DefaultRoleManager;
  await rm.addDomainMatchingFunc(keyMatch2Func);

  await testDomainEnforce(e, 'alice', 'domain1', 'data1', 'read', true);
  await testDomainEnforce(e, 'alice', 'domain1', 'data1', 'write', true);
  await testDomainEnforce(e, 'alice', 'domain1', 'data2', 'read', false);
  await testDomainEnforce(e, 'alice', 'domain1', 'data2', 'write', false);
  await testDomainEnforce(e, 'alice', 'domain2', 'data2', 'read', true);
  await testDomainEnforce(e, 'alice', 'domain2', 'data2', 'write', true);
  await testDomainEnforce(e, 'bob', 'domain2', 'data1', 'read', false);
  await testDomainEnforce(e, 'bob', 'domain2', 'data1', 'write', false);
  await testDomainEnforce(e, 'bob', 'domain2', 'data2', 'read', true);
  await testDomainEnforce(e, 'bob', 'domain2', 'data2', 'write', true);
});

test('TestAllMatchModel', async () => {
  const e = await newEnforcer('examples/rbac_with_all_pattern_model.conf', 'examples/rbac_with_all_pattern_policy.csv');

  const rm = e.getRoleManager() as DefaultRoleManager;
  await rm.addMatchingFunc(keyMatch2Func);
  await rm.addDomainMatchingFunc(keyMatch2Func);

  await testDomainEnforce(e, 'alice', 'domain1', '/book/1', 'read', true);
  await testDomainEnforce(e, 'alice', 'domain1', '/book/1', 'write', false);
  await testDomainEnforce(e, 'alice', 'domain2', '/book/1', 'read', false);
  await testDomainEnforce(e, 'alice', 'domain2', '/book/1', 'write', true);
});

test('ABACModelWithInOperator', async () => {
  const e = await newEnforcer('examples/in_operator_model.conf');

  class TestRule1 {
    public Owner: string;
    public Doc: string;

    constructor(Owner: string, Doc: string) {
      this.Owner = Owner;
      this.Doc = Doc;
    }
  }

  class TestRule2 {
    public Owner: string;
    public Docs: Array<string>;

    constructor(Owner: string, Doc: string[]) {
      this.Owner = Owner;
      this.Docs = Doc;
    }
  }

  const rule1 = new TestRule1('alice', 'aa');
  const rule2 = new TestRule2('alice', ['aa', 'bb']);

  await expect(e.enforce(rule1, rule2)).resolves.toBe(true);
});

test('InOperatorPrecedence', async () => {
  const run = async (matcher: string, sub: string, obj: any): Promise<boolean> => {
    const m = newModel();
    m.addDef('r', 'r', 'sub, obj');
    m.addDef('p', 'p', 'sub');
    m.addDef('e', 'e', 'some(where (p.eft == allow))');
    m.addDef('m', 'm', matcher);
    return newEnforcer(m, new StringAdapter('p, admin')).then((e) => e.enforce(sub, obj));
  };

  await expect(run('r.sub == p.sub && r.obj.IsPublic in [false]', 'guest', { IsPublic: false })).resolves.toBe(false);
  await expect(run('r.sub == p.sub && r.obj.IsPublic in [false]', 'admin', { IsPublic: false })).resolves.toBe(true);
  await expect(run('r.sub == p.sub || r.obj.Name in ["a"]', 'admin', { Name: 'b' })).resolves.toBe(true);
  await expect(run('r.sub == p.sub || r.obj.Name in ["a"]', 'guest', { Name: 'a' })).resolves.toBe(true);
  await expect(run('r.sub == p.sub || r.obj.Name in ["a"]', 'guest', { Name: 'b' })).resolves.toBe(false);
});
