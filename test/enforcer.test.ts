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

import fs, { readFileSync } from 'fs';

import { EnforceContext, Enforcer, FileAdapter, newEnforceContext, newEnforcer, newModel, StringAdapter, Util } from '../src';

async function testEnforce(e: Enforcer, sub: any, obj: string, act: string, res: boolean): Promise<void> {
  await expect(e.enforce(sub, obj, act)).resolves.toBe(res);
}

function testEnforceSync(e: Enforcer, sub: any, obj: string, act: string, res: boolean): void {
  expect(e.enforceSync(sub, obj, act)).toBe(res);
}

async function testEnforceEx(e: Enforcer, sub: any, obj: string, act: string, res: [boolean, string[]], domain?: string): Promise<void> {
  if (domain) {
    await expect(e.enforceEx(sub, obj, domain, act)).resolves.toEqual(res);
  } else {
    await expect(e.enforceEx(sub, obj, act)).resolves.toEqual(res);
  }
}

function testEnforceExSync(e: Enforcer, sub: any, obj: string, act: string, res: [boolean, string[]]): void {
  expect(e.enforceExSync(sub, obj, act)).toEqual(res);
}

async function testGetPolicy(e: Enforcer, res: string[][]): Promise<void> {
  const myRes = await e.getPolicy();
  console.log('Policy: ', myRes);

  expect(Util.array2DEquals(res, myRes)).toBe(true);
}

test('TestKeyMatchModelInMemory', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)');

  const a = new FileAdapter('examples/keymatch_policy.csv');

  let e = await newEnforcer(m, a);

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

  e = await newEnforcer(m);
  await a.loadPolicy(e.getModel());

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

test('TestKeyMatchModelInMemoryDeny', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('e', 'e', '!some(where (p.eft == deny))');
  m.addDef('m', 'm', 'r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)');

  const a = new FileAdapter('examples/keymatch_policy.csv');

  const e = await newEnforcer(m, a);

  await testEnforce(e, 'alice', '/alice_data/resource2', 'POST', true);
});

test('TestRBACModelInMemoryIndeterminate', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('g', 'g', '_, _');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act');

  const e = await newEnforcer(m);

  await e.addPermissionForUser('alice', 'data1', 'invalid');

  await testEnforce(e, 'alice', 'data1', 'read', false);
});

test('TestRBACModelInMemory', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('g', 'g', '_, _');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act');

  const e = await newEnforcer(m);

  await e.addPermissionForUser('alice', 'data1', 'read');
  await e.addPermissionForUser('bob', 'data2', 'write');
  await e.addPermissionForUser('data2_admin', 'data2', 'read');
  await e.addPermissionForUser('data2_admin', 'data2', 'write');
  await e.addRoleForUser('alice', 'data2_admin');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', true);
  await testEnforce(e, 'alice', 'data2', 'write', true);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);

  await e.deletePermissionForUser('alice', 'data1', 'read');
  await e.deletePermissionForUser('bob', 'data2', 'write');
  await e.deletePermissionForUser('data2_admin', 'data2', 'read');
  await e.deletePermissionForUser('data2_admin', 'data2', 'write');

  await testEnforce(e, 'alice', 'data1', 'read', false);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', false);

  await e.addPermissionForUser('bob', 'data2', 'write');
  await e.addPermissionForUser('data2_admin', 'data2', 'read');
  await e.addPermissionForUser('data2_admin', 'data2', 'write');
  await e.addRoleForUser('alice', 'data2_admin');

  await testEnforce(e, 'alice', 'data2', 'read', true);
  await testEnforce(e, 'alice', 'data2', 'write', true);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);

  await e.deletePermission('data2', 'write');

  await testEnforce(e, 'alice', 'data2', 'read', true);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', false);

  await e.addPermissionForUser('bob', 'data2', 'write');
  await e.addPermissionForUser('data2_admin', 'data2', 'read');
  await e.addPermissionForUser('data2_admin', 'data2', 'write');

  await testEnforce(e, 'alice', 'data2', 'read', true);
  await testEnforce(e, 'alice', 'data2', 'write', true);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);

  await e.deletePermissionsForUser('data2_admin');

  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestRBACModelInMemory2', async () => {
  const text = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`;
  const m = newModel(text);
  // The above is the same as:
  // const m = newModel();
  // m.loadModelFromText(text);

  const e = await newEnforcer(m);

  await e.addPermissionForUser('alice', 'data1', 'read');
  await e.addPermissionForUser('bob', 'data2', 'write');
  await e.addPermissionForUser('data2_admin', 'data2', 'read');
  await e.addPermissionForUser('data2_admin', 'data2', 'write');
  await e.addRoleForUser('alice', 'data2_admin');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', true);
  await testEnforce(e, 'alice', 'data2', 'write', true);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestNotUsedRBACModelInMemory', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('g', 'g', '_, _');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act');

  const e = await newEnforcer(m);

  await e.addPermissionForUser('alice', 'data1', 'read');
  await e.addPermissionForUser('bob', 'data2', 'write');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestReloadPolicy', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_policy.csv');

  await e.loadPolicy();
  await testGetPolicy(e, [
    ['alice', 'data1', 'read'],
    ['bob', 'data2', 'write'],
    ['data2_admin', 'data2', 'read'],
    ['data2_admin', 'data2', 'write'],
  ]);
});

test('TestSavePolicy', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_policy.csv');

  await e.savePolicy();
});

test('TestClearPolicy', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_policy.csv');

  e.clearPolicy();
});

test('TestEnableEnforce', async () => {
  const e = await newEnforcer('examples/basic_model.conf', 'examples/basic_policy.csv');

  e.enableEnforce(false);
  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', true);
  await testEnforce(e, 'alice', 'data2', 'read', true);
  await testEnforce(e, 'alice', 'data2', 'write', true);
  await testEnforce(e, 'bob', 'data1', 'read', true);
  await testEnforce(e, 'bob', 'data1', 'write', true);
  await testEnforce(e, 'bob', 'data2', 'read', true);
  await testEnforce(e, 'bob', 'data2', 'write', true);

  e.enableEnforce(true);
  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestEnableLog', async () => {
  const e = await newEnforcer('examples/basic_model.conf', 'examples/basic_policy.csv', true);
  // The log is enabled by default, so the above is the same with:
  // const e = await newEnforcer('examples/basic_model.conf', 'examples/basic_policy.csv');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);

  // The log can also be enabled or disabled at run-time.
  e.enableLog(false);
  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestEnableAutoSave', async () => {
  const e = await newEnforcer('examples/basic_model.conf', 'examples/basic_policy.csv');

  e.enableAutoSave(false);
  // Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
  // it doesn't affect the policy in the storage.
  await e.removePolicy('alice', 'data1', 'read');
  // Reload the policy from the storage to see the effect.
  await e.loadPolicy();
  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);

  e.enableAutoSave(true);
  // TODO debug
  // Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
  // but also affects the policy in the storage.
  // await e.removePolicy('alice', 'data1', 'read');

  // However, the file adapter doesn't implement the AutoSave feature, so enabling it has no effect at all here.

  // Reload the policy from the storage to see the effect.
  // await e.loadPolicy();
  await testEnforce(e, 'alice', 'data1', 'read', true); // Will not be false here.
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestInitWithAdapter', async () => {
  const adapter = new FileAdapter('examples/basic_policy.csv');
  const e = await newEnforcer('examples/basic_model.conf', adapter);

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestInitWithStringAdapter', async () => {
  const policy = readFileSync('examples/basic_policy.csv').toString();
  const adapter = new StringAdapter(policy);
  const e = await newEnforcer('examples/basic_model.conf', adapter);

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'write', false);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'bob', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'read', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
});

test('TestRoleLinks', async () => {
  const e = await newEnforcer('examples/rbac_model.conf');
  e.enableAutoBuildRoleLinks(false);
  await e.buildRoleLinks();
  await e.enforce('user501', 'data9', 'read');
});

test('TestGetAndSetModel', async () => {
  const e = await newEnforcer('examples/basic_model.conf', 'examples/basic_policy.csv');
  const e2 = await newEnforcer('examples/basic_with_root_model.conf', 'examples/basic_policy.csv');

  await testEnforce(e, 'root', 'data1', 'read', false);

  e.setModel(e2.getModel());

  await testEnforce(e, 'root', 'data1', 'read', true);
});

test('TestGetAndSetAdapterInMem', async () => {
  const e = await newEnforcer('examples/basic_model.conf', 'examples/basic_policy.csv');
  const e2 = await newEnforcer('examples/basic_model.conf', 'examples/basic_inverse_policy.csv');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);

  const a2 = e2.getAdapter();
  e.setAdapter(a2);
  await e.loadPolicy();
  await testEnforce(e, 'alice', 'data1', 'read', false);
  await testEnforce(e, 'alice', 'data1', 'write', true);
});

test('TestSetAdapterFromFile', async () => {
  const e = await newEnforcer('examples/basic_model.conf');

  await testEnforce(e, 'alice', 'data1', 'read', false);

  const a = new FileAdapter('examples/basic_policy.csv');
  e.setAdapter(a);
  await e.loadPolicy();

  await testEnforce(e, 'alice', 'data1', 'read', true);
});

test('TestSetAdapterFromString', async () => {
  const e = await newEnforcer('examples/basic_model.conf');

  await testEnforce(e, 'alice', 'data1', 'read', false);

  const policy = readFileSync('examples/basic_policy.csv').toString();

  const a = new StringAdapter(policy);
  e.setAdapter(a);
  await e.loadPolicy();

  await testEnforce(e, 'alice', 'data1', 'read', true);
});

test('TestInitEmpty with File Adapter', async () => {
  const e = await newEnforcer();

  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)');

  const a = new FileAdapter('examples/keymatch_policy.csv');

  e.setModel(m);
  e.setAdapter(a);
  await e.loadPolicy();

  await testEnforce(e, 'alice', '/alice_data/resource1', 'GET', true);
});

test('TestInitEmpty with String Adapter', async () => {
  const e = await newEnforcer();

  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)');

  const policy = readFileSync('examples/keymatch_policy.csv').toString();
  const a = new StringAdapter(policy);

  e.setModel(m);
  e.setAdapter(a);
  await e.loadPolicy();

  await testEnforce(e, 'alice', '/alice_data/resource1', 'GET', true);
});

describe('Unimplemented File Adapter methods', () => {
  let e = {} as Enforcer;
  let a = {} as FileAdapter;

  beforeEach(async () => {
    a = new FileAdapter('examples/basic_policy.csv');
    e = await newEnforcer('examples/basic_model.conf', a);
  });

  test('addPolicy', async () => {
    await expect(a.addPolicy('', '', [''])).rejects.toThrow('not implemented');
  });

  test('removePolicy', async () => {
    await expect(a.removePolicy('', '', [''])).rejects.toThrow('not implemented');
  });

  test('removeFilteredPolicy', async () => {
    await expect(a.removeFilteredPolicy('', '', 0, '')).rejects.toThrow('not implemented');
  });
});

describe('Unimplemented String Adapter methods', () => {
  let e = {} as Enforcer;
  let a = {} as StringAdapter;

  beforeEach(async () => {
    const policy = readFileSync('examples/basic_policy.csv').toString();
    a = new StringAdapter(policy);
    e = await newEnforcer('examples/basic_model.conf', a);
  });

  test('savePolicy', async () => {
    await expect(a.savePolicy(e.getModel())).rejects.toThrow('not implemented');
  });

  test('addPolicy', async () => {
    await expect(a.addPolicy('', '', [''])).rejects.toThrow('not implemented');
  });

  test('removePolicy', async () => {
    await expect(a.removePolicy('', '', [''])).rejects.toThrow('not implemented');
  });

  test('removeFilteredPolicy', async () => {
    await expect(a.removeFilteredPolicy('', '', 0, '')).rejects.toThrow('not implemented');
  });
});

class TestSub {
  Name: string;
  Age: number;

  constructor(name: string, age: number) {
    this.Name = name;
    this.Age = age;
  }

  toJSONString(): string {
    return JSON.stringify(this);
  }
}

test('test ABAC Scaling', async () => {
  const e = await newEnforcer('examples/abac_rule_model.conf', 'examples/abac_rule_policy.csv');

  const sub1 = new TestSub('alice', 16);
  const sub2 = new TestSub('alice', 20);
  const sub3 = new TestSub('alice', 65);

  await testEnforce(e, sub1, '/data1', 'read', false);
  await testEnforce(e, sub1, '/data2', 'read', false);
  await testEnforce(e, sub1, '/data1', 'write', false);
  await testEnforce(e, sub1, '/data2', 'write', true);
  await testEnforce(e, sub2, '/data1', 'read', true);
  await testEnforce(e, sub2, '/data2', 'read', false);
  await testEnforce(e, sub2, '/data1', 'write', false);
  await testEnforce(e, sub2, '/data2', 'write', true);
  await testEnforce(e, sub3, '/data1', 'read', true);
  await testEnforce(e, sub3, '/data2', 'read', false);
  await testEnforce(e, sub3, '/data1', 'write', false);
  await testEnforce(e, sub3, '/data2', 'write', false);
});

test('test ABAC multiple eval()', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub_rule_1, sub_rule_2, act');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'eval(p.sub_rule_1) && eval(p.sub_rule_2) && r.act == p.act');

  const policy = new StringAdapter(
    `
    p, r.sub > 50, r.obj > 50, read
    `
  );

  const e = await newEnforcer(m, policy);
  await testEnforce(e, 56, (98 as unknown) as string, 'read', true);
  await testEnforce(e, 23, (67 as unknown) as string, 'read', false);
  await testEnforce(e, 78, (34 as unknown) as string, 'read', false);
});

// https://github.com/apache/casbin-node-casbin/issues/438
test('test ABAC single eval() with r. in unexpected places', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub_rule, act');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'eval(p.sub_rule) && r.act == p.act');

  const policy = new StringAdapter(
    `
    p, !!r.sub.id && r.sub.id == r.obj.owner.id, read
    `
  );

  const e = await newEnforcer(m, policy);
  await testEnforce(e, { id: 3 }, ({ owner: { id: 3 } } as unknown) as string, 'read', true);
  await testEnforce(e, {}, ({ owner: {} } as unknown) as string, 'read', false);
  await testEnforce(e, { id: 3 }, ({ owner: {} } as unknown) as string, 'read', false);
  await testEnforce(e, { id: 3 }, ({ owner: { id: 2 } } as unknown) as string, 'read', false);
});

test('test escapeAssertion with string literals (issue)', async () => {
  // Test case from GitHub issue: escapeAssertion should not replace r./p. inside string literals
  const MY_RESOURCE_NAME = 'r.my_resource';
  const model = newModel();
  model.addDef('r', 'r', 'act, obj');
  model.addDef('p', 'p', 'act, obj, rule');
  model.addDef('e', 'e', 'some(where (p.eft == allow))');
  model.addDef('m', 'm', 'r.act == p.act && r.obj == p.obj && eval(p.rule)');

  const enforcer = await newEnforcer(model);
  enforcer.addPolicy('alice', MY_RESOURCE_NAME, `p.obj == "${MY_RESOURCE_NAME}"`);

  // Should work because string literals are not escaped
  await expect(enforcer.enforce('alice', MY_RESOURCE_NAME)).resolves.toBe(true);

  // Test with single quotes as well
  enforcer.addPolicy('bob', 'p.resource', `p.obj == 'p.resource'`);
  await expect(enforcer.enforce('bob', 'p.resource')).resolves.toBe(true);
});

test('TestEnforceSync', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('g', 'g', '_, _');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act');

  const e = await newEnforcer(m);

  await e.addPermissionForUser('alice', 'data1', 'invalid');

  testEnforceSync(e, 'alice', 'data1', 'read', false);
});

test('TestEnforceEx', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('g', 'g', '_, _');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act');

  const e = await newEnforcer(m);

  await e.addPermissionForUser('alice', 'data1', 'invalid');

  testEnforceEx(e, 'alice', 'data1', 'read', [false, []]);
  testEnforceEx(e, 'alice', 'data1', 'invalid', [true, ['alice', 'data1', 'invalid']]);
});

test('TestSyncEnforceEx', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('g', 'g', '_, _');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act');

  const e = await newEnforcer(m);

  await e.addPermissionForUser('alice', 'data1', 'invalid');

  testEnforceExSync(e, 'alice', 'data1', 'read', [false, []]);
  testEnforceExSync(e, 'alice', 'data1', 'invalid', [true, ['alice', 'data1', 'invalid']]);
});

test('Test RBAC G2', async () => {
  const e = await newEnforcer('examples/rbac_g2_model.conf', 'examples/rbac_g2_policy.csv');
  expect(await e.enforce('alice', 'data1', 'read')).toBe(false);
  expect(await e.enforce('admin', 'data1', 'read')).toBe(true);
});

test('TestBatchEnforce', async () => {
  const e = await newEnforcer('examples/basic_model.conf', 'examples/basic_policy.csv');
  const requests: string[][] = [
    ['alice', 'data1', 'read'],
    ['bob', 'data2', 'write'],
  ];
  expect(await e.batchEnforce(requests)).toEqual([true, true]);
});

test('TestKeyGet2', async () => {
  const e = await newEnforcer('examples/basic_keyget2_model.conf', 'examples/basic_keyget2_policy.csv');
  expect(await e.enforce('alice', 'data')).toBe(false);
  expect(await e.enforce('alice', '/data')).toBe(false);
  expect(await e.enforce('alice', '/data/1')).toBe(true);
});

test('TestEnforceExWithRBACDenyModel', async () => {
  const e = await newEnforcer('examples/rbac_with_deny_model.conf', 'examples/rbac_with_deny_policy.csv');
  testEnforceEx(e, 'alice', 'data1', 'read', [true, ['alice', 'data1', 'read', 'allow']]);
  testEnforceEx(e, 'bob', 'data2', 'write', [true, ['bob', 'data2', 'write', 'allow']]);
  testEnforceEx(e, 'alice', 'data2', 'write', [false, ['alice', 'data2', 'write', 'deny']]);
  testEnforceEx(e, 'data2_admin', 'data2', 'read', [true, ['data2_admin', 'data2', 'read', 'allow']]);
  testEnforceEx(e, 'data2_admin', 'data2', 'write', [true, ['data2_admin', 'data2', 'write', 'allow']]);
  testEnforceEx(e, 'data2_admin', 'data1', 'read', [false, []]);
  testEnforceEx(e, 'data2_admin', 'data1', 'write', [false, []]);
});

test('TestEnforceExWithGlobModel', async () => {
  const e = await newEnforcer('examples/glob_model.conf', 'examples/glob_policy.csv');
  testEnforceEx(e, 'u1', '/foo/1', 'read', [true, ['u1', '/foo/*', 'read']]);
  testEnforceEx(e, 'u2', '/foo1', 'read', [true, ['u2', '/foo*', 'read']]);
  testEnforceEx(e, 'u3', '/foo/2', 'read', [false, []]);
});

test('TestEnforceExWithKeyMatchModel', async () => {
  const e = await newEnforcer('examples/keymatch_model.conf', 'examples/keymatch_policy.csv');
  testEnforceEx(e, 'alice', '/alice_data/1', 'GET', [true, ['alice', '/alice_data/*', 'GET']]);
  testEnforceEx(e, 'bob', '/alice_data/1', 'POST', [false, []]);
});

test('TestEnforceExWithPriorityModel', async () => {
  const e = await newEnforcer('examples/priority_model.conf', 'examples/priority_policy.csv');
  testEnforceEx(e, 'alice', 'data1', 'read', [true, ['alice', 'data1', 'read', 'allow']]);
  testEnforceEx(e, 'bob', 'data2', 'read', [true, ['data2_allow_group', 'data2', 'read', 'allow']]);
  testEnforceEx(e, 'alice', 'data2', 'read', [false, []]);
});

test('TestSubjectPriority', async () => {
  const e = await newEnforcer('examples/subject_priority_model.conf', 'examples/subject_priority_policy.csv');
  testEnforceEx(e, 'jane', 'data1', 'read', [true, ['jane', 'data1', 'read', 'allow']]);
  testEnforceEx(e, 'alice', 'data1', 'read', [true, ['alice', 'data1', 'read', 'allow']]);
});

test('TestSubjectPriority with CSV converted to addPolicy/addGroupingPolicy', async () => {
  const e = await newEnforcer('examples/subject_priority_model.conf');

  await e.addPolicy('root', 'data1', 'read', 'deny');
  await e.addPolicy('admin', 'data1', 'read', 'deny');
  await e.addPolicy('editor', 'data1', 'read', 'deny');
  await e.addPolicy('subscriber', 'data1', 'read', 'deny');
  await e.addPolicy('jane', 'data1', 'read', 'allow');
  await e.addPolicy('alice', 'data1', 'read', 'allow');

  await e.addGroupingPolicy('admin', 'root');
  await e.addGroupingPolicy('editor', 'admin');
  await e.addGroupingPolicy('subscriber', 'admin');
  await e.addGroupingPolicy('jane', 'editor');
  await e.addGroupingPolicy('alice', 'subscriber');

  testEnforceEx(e, 'jane', 'data1', 'read', [true, ['jane', 'data1', 'read', 'allow']]);
  testEnforceEx(e, 'alice', 'data1', 'read', [true, ['alice', 'data1', 'read', 'allow']]);
});

test('TestSubjectPriority simpler with CSV', async () => {
  const e = await newEnforcer('examples/subject_priority_model.conf', 'examples/subject_priority_policy_simple.csv');

  testEnforceEx(e, 'user', 'data1', 'read', [true, ['user', 'data1', 'read', 'allow']]);
});

test('TestSubjectPriority simpler with addPolicy', async () => {
  const e = await newEnforcer('examples/subject_priority_model.conf');

  await e.addPolicy('group', 'data1', 'read', 'deny');
  await e.addPolicy('user', 'data1', 'read', 'allow');
  await e.addGroupingPolicy('user', 'group');

  testEnforceEx(e, 'user', 'data1', 'read', [true, ['user', 'data1', 'read', 'allow']]);
});

test('TestSubjectPriorityWithDomain', async () => {
  const e = await newEnforcer('examples/subject_priority_model_with_domain.conf', 'examples/subject_priority_policy_with_domain.csv');
  testEnforceEx(e, 'alice', 'data1', 'write', [true, ['alice', 'data1', 'domain1', 'write', 'allow']], 'domain1');
  testEnforceEx(e, 'bob', 'data2', 'write', [true, ['bob', 'data2', 'domain2', 'write', 'allow']], 'domain2');
});

test('TestEnforcerWithScopeFileSystem', async () => {
  const e = await newEnforcer();
  const defaultFileSystem = {
    readFileSync(path: string, encoding?: string) {
      return fs.readFileSync(path, { encoding });
    },
    writeFileSync(path: string, text: string, encoding?: string) {
      return fs.writeFileSync(path, text, encoding);
    },
  };
  e.setFileSystem(defaultFileSystem);
  expect(e.getFileSystem()).toEqual(defaultFileSystem);
  await e.initWithFile('examples/basic_model.conf', 'examples/basic_policy.csv', false);
  await testEnforce(e, 'alice', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await testEnforce(e, 'bob', 'data2', 'write', true);
  await testEnforce(e, 'bob', 'data2', 'read', false);
});

test('TestEnforce Multiple policies config', async () => {
  const m = newModel();
  m.addDef('r', 'r2', 'sub, obj, act');
  m.addDef('p', 'p2', 'sub, obj, act');
  m.addDef('g', 'g', '_, _');
  m.addDef('e', 'e2', 'some(where (p.eft == allow))');
  m.addDef('m', 'm2', 'g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act');
  const a = new FileAdapter('examples/mulitple_policy.csv');

  const e = await newEnforcer(m, a);

  //const e = await getEnforcerWithPath(m);
  const enforceContext = new EnforceContext('r2', 'p2', 'e2', 'm2');
  await expect(e.enforce(enforceContext, 'alice', 'data1', 'read')).resolves.toStrictEqual(true);
  await expect(e.enforce(enforceContext, 'bob', 'data2', 'write')).resolves.toStrictEqual(true);
});

test('new EnforceContext config', async () => {
  const m = newModel();
  m.addDef('r', 'r2', 'sub, obj, act');
  m.addDef('p', 'p2', 'sub, obj, act');
  m.addDef('g', 'g', '_, _');
  m.addDef('e', 'e2', 'some(where (p.eft == allow))');
  m.addDef('m', 'm2', 'g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act');
  const a = new FileAdapter('examples/mulitple_policy.csv');

  const e = await newEnforcer(m, a);

  //const e = await getEnforcerWithPath(m);
  const enforceContext = newEnforceContext('2');
  await expect(e.enforce(enforceContext, 'alice', 'data1', 'read')).resolves.toStrictEqual(true);
  await expect(e.enforce(enforceContext, 'bob', 'data2', 'write')).resolves.toStrictEqual(true);
});

test('TestEnforceEX Multiple policies config', async () => {
  const m = newModel();
  m.addDef('r', 'r2', 'sub, obj, act');
  m.addDef('p', 'p2', 'sub, obj, act');
  m.addDef('g', 'g', '_, _');
  m.addDef('e', 'e2', 'some(where (p.eft == allow))');
  m.addDef('m', 'm2', 'g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act');
  const a = new FileAdapter('examples/mulitple_policy.csv');

  const e = await newEnforcer(m, a);

  //const e = await getEnforcerWithPath(m);
  const enforceContext = new EnforceContext('r2', 'p2', 'e2', 'm2');
  await expect(e.enforceEx(enforceContext, 'alice', 'data1', 'read')).resolves.toStrictEqual([true, ['alice', 'data1', 'read']]);
  await expect(e.enforceEx(enforceContext, 'bob', 'data2', 'write')).resolves.toStrictEqual([true, ['bob', 'data2', 'write']]);
});

test('new EnforceContextEX config', async () => {
  const m = newModel();
  m.addDef('r', 'r2', 'sub, obj, act');
  m.addDef('p', 'p2', 'sub, obj, act');
  m.addDef('g', 'g', '_, _');
  m.addDef('e', 'e2', 'some(where (p.eft == allow))');
  m.addDef('m', 'm2', 'g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act');
  const a = new FileAdapter('examples/mulitple_policy.csv');

  const e = await newEnforcer(m, a);

  //const e = await getEnforcerWithPath(m);
  const enforceContext = newEnforceContext('2');
  await expect(e.enforceEx(enforceContext, 'alice', 'data1', 'read')).resolves.toStrictEqual([true, ['alice', 'data1', 'read']]);
  await expect(e.enforceEx(enforceContext, 'bob', 'data2', 'write')).resolves.toStrictEqual([true, ['bob', 'data2', 'write']]);
});

test('TestEnforceWithMatcher', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_policy.csv');
  expect(await e.enforce('bob', 'data2', 'read')).toBe(false);
  expect(await e.enforce('bob', 'data1', 'read')).toBe(false);
  expect(await e.enforce('alice', 'data1', 'write')).toBe(false);
  expect(await e.enforce('data2_admin', 'data1', 'read')).toBe(false);
  expect(await e.enforce('data2_admin', 'data1', 'write')).toBe(false);
  const m1 = 'g(r.sub, p.sub) && r.obj == p.obj';
  expect(await e.enforceWithMatcher(m1, 'bob', 'data2', 'read')).toBe(true);
  expect(await e.enforceWithMatcher(m1, 'alice', 'data1', 'write')).toBe(true);
  const m2 = 'g(r.sub, p.sub)';
  expect(await e.enforceWithMatcher(m2, 'bob', 'data1', 'read')).toBe(true);
  expect(await e.enforceWithMatcher(m2, 'data2_admin', 'data1', 'read')).toBe(true);
  expect(await e.enforceWithMatcher(m2, 'data2_admin', 'data1', 'write')).toBe(true);
});

test('TestEnforceWithEnableAcceptJsonRequest', async () => {
  const e = await newEnforcer('examples/abac_rule_model.conf', 'examples/abac_rule_policy.csv');
  e.enableAcceptJsonRequest(true);

  const sub1 = new TestSub('alice', 16).toJSONString();
  const sub2 = new TestSub('alice', 20).toJSONString();
  const sub3 = new TestSub('alice', 65).toJSONString();

  await testEnforce(e, sub1, '/data1', 'read', false);
  await testEnforce(e, sub1, '/data2', 'read', false);
  await testEnforce(e, sub1, '/data1', 'write', false);
  await testEnforce(e, sub1, '/data2', 'write', true);
  await testEnforce(e, sub2, '/data1', 'read', true);
  await testEnforce(e, sub2, '/data2', 'read', false);
  await testEnforce(e, sub2, '/data1', 'write', false);
  await testEnforce(e, sub2, '/data2', 'write', true);
  await testEnforce(e, sub3, '/data1', 'read', true);
  await testEnforce(e, sub3, '/data2', 'read', false);
  await testEnforce(e, sub3, '/data1', 'write', false);
  await testEnforce(e, sub3, '/data2', 'write', false);

  e.enableAcceptJsonRequest(false);
  await testEnforce(e, sub1, '/data2', 'write', false);
  await testEnforce(e, sub2, '/data1', 'read', false);
  await testEnforce(e, sub2, '/data2', 'write', false);
  await testEnforce(e, sub3, '/data1', 'read', false);
});
