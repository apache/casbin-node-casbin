// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import { Enforcer, newCachedEnforcer, newModel } from '../src';

async function testEnforce(e: Enforcer, sub: string, obj: string, act: string, res: boolean): Promise<void> {
  await expect(e.enforce(sub, obj, act)).resolves.toBe(res);
}

test('TestRBACModel', async () => {
  const e = await newCachedEnforcer('examples/rbac_model.conf', 'examples/rbac_policy.csv');

  await testEnforce(e, 'alice', 'data1', 'read', true);
});

test('TestCacheInvalidatedOnPolicyChange', async () => {
  const e = await newCachedEnforcer('examples/basic_model.conf', 'examples/basic_policy.csv');

  await testEnforce(e, 'alice', 'data1', 'read', true);
  await e.removePolicy('alice', 'data1', 'read');
  await testEnforce(e, 'alice', 'data1', 'read', false);
  await e.addPolicy('alice', 'data1', 'read');
  await testEnforce(e, 'alice', 'data1', 'read', true);
  await e.updatePolicy(['alice', 'data1', 'read'], ['alice', 'data1', 'write']);
  await testEnforce(e, 'alice', 'data1', 'read', false);
  e.clearPolicy();
  await testEnforce(e, 'alice', 'data1', 'write', false);
  await e.loadPolicy();
  await testEnforce(e, 'alice', 'data1', 'read', true);
});

test('TestCacheInvalidatedOnRoleChange', async () => {
  const e = await newCachedEnforcer('examples/rbac_model.conf', 'examples/rbac_policy.csv');

  await testEnforce(e, 'alice', 'data2', 'read', true);
  await e.deleteRoleForUser('alice', 'data2_admin');
  await testEnforce(e, 'alice', 'data2', 'read', false);
});

test('TestCacheNotWrittenWhenPolicyChangesDuringEnforce', async () => {
  const m = newModel();
  m.addDef('r', 'r', 'sub, obj, act');
  m.addDef('p', 'p', 'sub, obj, act');
  m.addDef('e', 'e', 'some(where (p.eft == allow))');
  m.addDef('m', 'm', 'r.sub == p.sub && r.obj == p.obj && r.act == p.act && slow()');
  const e = await newCachedEnforcer(m);
  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => (release = resolve));
  let wait = false;
  await e.addFunction('slow', async () => {
    if (wait) {
      await gate;
    }
    return true;
  });
  await e.addPolicy('alice', 'data1', 'read');

  wait = true;
  const pending = e.enforce('alice', 'data1', 'read');
  await new Promise((resolve) => setImmediate(resolve));
  wait = false;
  await e.removePolicy('alice', 'data1', 'read');
  await testEnforce(e, 'alice', 'data1', 'read', false);
  release();
  await expect(pending).resolves.toBe(true);

  await testEnforce(e, 'alice', 'data1', 'read', false);
});

test('TestCacheWithEnableEnforce', async () => {
  const e = await newCachedEnforcer('examples/basic_model.conf', 'examples/basic_policy.csv');

  await testEnforce(e, 'bob', 'data1', 'read', false);
  e.enableEnforce(false);
  await testEnforce(e, 'bob', 'data1', 'read', true);
  await testEnforce(e, 'alice', 'data2', 'read', true);
  e.enableEnforce(true);
  await testEnforce(e, 'bob', 'data1', 'read', false);
  await testEnforce(e, 'alice', 'data2', 'read', false);
});

test('TestCacheKeysDoNotCollide', async () => {
  const e = await newCachedEnforcer('examples/basic_model.conf');
  await e.addPolicy('alice', 'data1$$read', 'write');

  await testEnforce(e, 'alice', 'data1$$read', 'write', true);
  await testEnforce(e, 'alice$$data1', 'read', 'write', false);
});
