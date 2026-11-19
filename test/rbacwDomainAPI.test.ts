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

import { newEnforcer } from '../src';

test('test getRolesForUserInDomain', async () => {
  const e = await newEnforcer('examples/rbac_with_domains_model.conf', 'examples/rbac_with_domains_policy.csv');
  expect(await e.getRolesForUserInDomain('alice', 'domain1')).toEqual(['admin']);
  expect(await e.getRolesForUserInDomain('alice', 'domain2')).toEqual([]);
  expect(await e.getRolesForUserInDomain('bob', 'domain1')).toEqual([]);
  expect(await e.getRolesForUserInDomain('bob', 'domain2')).toEqual(['admin']);
});

test('test getUsersForRoleInDomain', async () => {
  const e = await newEnforcer('examples/rbac_with_domains_model.conf', 'examples/rbac_with_domains_policy.csv');
  expect(await e.getUsersForRoleInDomain('admin', 'domain1')).toEqual(['alice']);
  expect(await e.getUsersForRoleInDomain('admin', 'domain2')).toEqual(['bob']);
  expect(await e.getUsersForRoleInDomain('superadmin', 'domain1')).toEqual([]);
  expect(await e.getUsersForRoleInDomain('superadmin', 'domain2')).toEqual([]);
});

test('test getDomainsForUser', async () => {
  const e = await newEnforcer('examples/rbac_with_domains_model.conf', 'examples/rbac_with_domains_policy2.csv');

  let myRes = await e.getDomainsForUser('alice');
  myRes.sort();
  expect(myRes).toEqual(['domain1', 'domain2']);

  myRes = await e.getDomainsForUser('bob');
  myRes.sort();
  expect(myRes).toEqual(['domain2', 'domain3']);

  myRes = await e.getDomainsForUser('user');
  expect(myRes).toEqual(['domain3']);
});

test('test getAllDomains', async () => {
  const e = await newEnforcer('examples/rbac_with_domains_model.conf', 'examples/rbac_with_domains_policy.csv');

  const myRes = await e.getAllDomains();
  myRes.sort();
  expect(myRes).toEqual(['domain1', 'domain2']);
});
