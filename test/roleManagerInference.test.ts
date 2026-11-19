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

import { newEnforcer, newModelFromString, Util } from '../src';

const base = 'g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act';

async function enforcer(matcher: string, policyDomain = 'tenant-b'): Promise<any> {
  const model = newModelFromString(`[request_definition]
r = sub, dom, obj, act
[policy_definition]
p = sub, dom, obj, act
[role_definition]
g = _, _, _
g2 = _, _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = ${matcher}`);
  const e = await newEnforcer(model);
  await e.addGroupingPolicy('alice', 'admin', 'tenant*');
  await e.addPolicy('admin', policyDomain, 'data1', 'read');
  return e;
}

test.each([
  '',
  ' && "keyMatch(r_dom, p_dom)" == "keyMatch(r_dom, p_dom)"',
  " && 'keyMatch(r_dom, p_dom)' == 'keyMatch(r_dom, p_dom)'",
  ' && (true || keyMatch(r.dom, p.dom))',
  ' && !(false && keyMatch(r.dom, p.dom))',
])('domain isolation is unchanged by an optional or quoted condition: %s', async (extra) => {
  const e = await enforcer(base + extra);
  await expect(e.enforce('alice', 'tenant-b', 'data1', 'read')).resolves.toBe(false);
});

test.each(['keyMatch(r.dom, p.dom)', 'keyMatch(r.dom,p.dom)', 'keyMatch( r.dom , p.dom )'])(
  'required domain matching preserves pattern-role support: %s',
  async (match) => {
    const e = await enforcer(`g(r.sub, p.sub, r.dom) && (${match}) && r.obj == p.obj && r.act == p.act`, 'tenant*');
    await expect(e.enforce('alice', 'tenant-b', 'data1', 'read')).resolves.toBe(true);
    await expect(e.enforce('alice', 'other', 'data1', 'read')).resolves.toBe(false);
  }
);

test('a resource pattern is not inferred as a domain pattern', async () => {
  const model = newModelFromString(`[request_definition]
r = sub, obj, dom, act
[policy_definition]
p = sub, obj, dom, act
[role_definition]
g = _, _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch(r.obj, p.obj) && r.act == p.act`);
  const e = await newEnforcer(model);
  await e.addGroupingPolicy('alice', 'admin', 'tenant*');
  await e.addPolicy('admin', 'data*', 'tenant-b', 'read');
  await expect(e.enforce('alice', 'data1', 'tenant-b', 'read')).resolves.toBe(false);
});

test('domain inference is scoped to the required role function', async () => {
  const e = await enforcer('g(r.sub, p.sub, r.dom) && keyMatch(r.dom, p.dom) && r.obj == p.obj && r.act == p.act', 'tenant*');
  await e.addNamedGroupingPolicy('g2', 'alice', 'admin', 'tenant*');
  await expect(e.enforce('alice', 'tenant-b', 'data1', 'read')).resolves.toBe(true);
  await expect(e.getNamedRoleManager('g2').hasLink('alice', 'admin', 'tenant-b')).resolves.toBe(false);
});

test('explicit domain matching remains available for exact-domain models', async () => {
  const e = await enforcer(base);
  await e.getRoleManager().addDomainMatchingFunc(Util.keyMatchFunc);
  await expect(e.enforce('alice', 'tenant-b', 'data1', 'read')).resolves.toBe(true);
});
