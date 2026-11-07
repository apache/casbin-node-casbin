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
import { DefaultRoleManager, newSyncedEnforcer, RoleManager, SyncedEnforcer } from '../src';

describe('Test Hierarchical Domain RBAC', () => {
  let e: SyncedEnforcer;
  beforeAll(async () => {
    e = await newSyncedEnforcer('examples/rbac_with_hierarchical_domains_model.conf', 'examples/rbac_with_hierarchical_domains_policy.csv');
    await (e.getRoleManager() as DefaultRoleManager).addDomainHierarchy(e.getNamedRoleManager('g2') as RoleManager);
  });

  test('Authorization to lower domain should pass', async () => {
    expect(e.enforceSync('alice', 'domain1', 'data1', 'read')).toBe(true);
    expect(e.enforceSync('alice', 'domain1', 'data2', 'read')).toBe(true);
    expect(e.enforceSync('alice', 'domain2', 'data2', 'read')).toBe(true);
    expect(e.enforceSync('alice', 'domain1', 'sdata2', 'read')).toBe(true);
    expect(e.enforceSync('alice', 'sibling2', 'sdata2', 'read')).toBe(true);
    expect(e.enforceSync('alice', 'domain3', 'data3', 'write')).toBe(true);
    expect(e.enforceSync('alice', 'domain1', 'data3', 'write')).toBe(true);
    expect(e.enforceSync('alice', 'domain2', 'data3', 'write')).toBe(true);
    expect(e.enforceSync('bob', 'domain2', 'data2', 'read')).toBe(true);
    expect(e.enforceSync('bob', 'domain2', 'data3', 'write')).toBe(true);
    expect(e.enforceSync('bob', 'domain3', 'data3', 'write')).toBe(true);
  });

  test('Authorization to lower domain should faill if no role', async () => {
    expect(e.enforceSync('bob', 'domain1', 'data3', 'write')).toBe(false);
    expect(e.enforceSync('bob', 'domain1', 'data2', 'read')).toBe(false);
  });

  test('Authorization to higher domain without permissions should faill', async () => {
    expect(e.enforceSync('bob', 'domain1', 'data1', 'read')).toBe(false);
    expect(e.enforceSync('bob', 'domain2', 'data1', 'read')).toBe(false);
    expect(e.enforceSync('bob', 'domain3', 'data1', 'write')).toBe(false);
  });

  test('Authorization to higher domain with permissions should faill', async () => {
    // alice data1
    expect(e.enforceSync('alice', 'domain2', 'data1', 'read')).toBe(false);
    expect(e.enforceSync('alice', 'domain3', 'data1', 'read')).toBe(false);
    expect(e.enforceSync('alice', 'sibling2', 'data1', 'read')).toBe(false);
    // alice data2
    expect(e.enforceSync('alice', 'domain3', 'data2', 'read')).toBe(false);
    expect(e.enforceSync('alice', 'sibling2', 'data2', 'read')).toBe(false);
    // alice data3
    expect(e.enforceSync('alice', 'sibling2', 'data3', 'write')).toBe(false);
    // alice sdata2
    expect(e.enforceSync('alice', 'domain2', 'sdata2', 'read')).toBe(false);
    // bob data2
    expect(e.enforceSync('bob', 'domain3', 'data2', 'read')).toBe(false);
  });

  test('Authorization to sibling without permissions should faill', async () => {
    expect(e.enforceSync('bob', 'domain1', 'sdata2', 'read')).toBe(false);
    expect(e.enforceSync('bob', 'domain2', 'sdata2', 'read')).toBe(false);
    expect(e.enforceSync('bob', 'sibling2', 'sdata2', 'read')).toBe(false);
    expect(e.enforceSync('bob', 'domain3', 'sdata2', 'read')).toBe(false);
  });

  test('User should not have a permission if there is none in the lower domain', async () => {
    expect(e.enforceSync('alice', 'domain3', 'data3', 'read')).toBe(false);
    expect(e.enforceSync('bob', 'domain3', 'data3', 'read')).toBe(false);
  });

  test('test getRolesForUserInDomain', async () => {
    expect(await e.getRolesForUserInDomain('alice', 'domain1')).toEqual(['admin']);
    expect(await e.getRolesForUserInDomain('alice', 'domain2')).toEqual(['admin']);
    expect(await e.getRolesForUserInDomain('alice', 'domain3')).toEqual(['admin']);
    expect(await e.getRolesForUserInDomain('alice', 'sibling2')).toEqual(['admin']);
    expect(await e.getRolesForUserInDomain('bob', 'domain1')).toEqual([]);
    expect(await e.getRolesForUserInDomain('bob', 'domain2')).toEqual(['admin']);
    expect(await e.getRolesForUserInDomain('bob', 'domain3')).toEqual(['admin']);
  });

  test('test getUsersForRoleInDomain', async () => {
    expect(await e.getUsersForRoleInDomain('admin', 'domain1')).toEqual(['alice']);
    expect(await e.getUsersForRoleInDomain('admin', 'domain2')).toEqual(['bob', 'alice']);
    expect(await e.getUsersForRoleInDomain('admin', 'sibling2')).toEqual(['alice']);
    expect(await e.getUsersForRoleInDomain('admin', 'domain3')).toEqual(['alice', 'bob']);
  });
});
