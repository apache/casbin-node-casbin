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
import { keyMatchFunc } from '../src/util';

test('test getRolesForUser', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.getRolesForUser('alice')).toEqual(['admin']);
});

test('test getRolesForUser with domain', async () => {
  const e = await newEnforcer('examples/rbac_with_domains_model.conf', 'examples/rbac_with_hierarchy_with_domains_policy.csv');
  expect(await e.getRolesForUser('alice', 'domain1')).toEqual(['role:global_admin']);
});

test('test add/deleteRoleForUSer with domain', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.getRolesForUser('bob')).toEqual([]);
  expect(await e.addRoleForUser('bob', 'data1_admin')).toEqual(true);
  expect(await e.hasRoleForUser('bob', 'data1_admin')).toEqual(true);
  expect(await e.getUsersForRole('data1_admin')).toEqual(['admin', 'bob']);
  expect(await e.deleteRoleForUser('bob', 'data1_admin')).toEqual(true);
  expect(await e.hasRoleForUser('bob', 'role:global_admin')).toEqual(false);
  expect(await e.getUsersForRole('data1_admin')).toEqual(['admin']);
});

test('test add/deleteRoleForUSer with domain', async () => {
  const e = await newEnforcer('examples/rbac_with_domains_model.conf', 'examples/rbac_with_hierarchy_with_domains_policy.csv');
  expect(await e.getRolesForUser('bob', 'domain1')).toEqual([]);
  expect(await e.addRoleForUser('bob', 'role:global_admin', 'domain1')).toEqual(true);
  expect(await e.hasRoleForUser('bob', 'role:global_admin', 'domain1')).toEqual(true);
  expect(await e.getUsersForRole('role:global_admin', 'domain1')).toEqual(['alice', 'bob']);
  expect(await e.deleteRoleForUser('bob', 'role:global_admin', 'domain1')).toEqual(true);
  expect(await e.hasRoleForUser('bob', 'role:global_admin', 'domain1')).toEqual(false);
  expect(await e.getUsersForRole('role:global_admin', 'domain1')).toEqual(['alice']);
});

test('test getImplicitRolesForUser', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.getImplicitRolesForUser('bob')).toEqual([]);
  expect(await e.getImplicitRolesForUser('alice')).toEqual(['admin', 'data1_admin', 'data2_admin']);
});

test('test getImplicitRolesForUser with domain', async () => {
  const e = await newEnforcer('examples/rbac_with_domains_model.conf', 'examples/rbac_with_hierarchy_with_domains_policy.csv');
  expect(await e.getImplicitRolesForUser('alice', 'domain1')).toEqual(['role:global_admin', 'role:reader', 'role:writer']);
});

test('test getImplicitPermissionsForUser', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.hasPermissionForUser('bob', 'data2', 'write')).toEqual(true);
  expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
  expect(await e.hasPermissionForUser('alice', 'data1', 'read')).toEqual(true);
  expect(await e.hasPermissionForUser('data1_admin', 'data1', 'read')).toEqual(true);
  expect(await e.hasPermissionForUser('data1_admin', 'data1', 'write')).toEqual(true);
  expect(await e.hasPermissionForUser('data2_admin', 'data2', 'read')).toEqual(true);
  expect(await e.hasPermissionForUser('data2_admin', 'data2', 'write')).toEqual(true);
  expect(await e.getImplicitPermissionsForUser('alice')).toEqual([
    ['alice', 'data1', 'read'],
    ['data1_admin', 'data1', 'read'],
    ['data1_admin', 'data1', 'write'],
    ['data2_admin', 'data2', 'read'],
    ['data2_admin', 'data2', 'write'],
  ]);
});

test('test getImplicitRolesForUser walks each role definition separately', async () => {
  const e = await newEnforcer('examples/rbac_with_multiple_policy_model.conf', 'examples/rbac_with_multiple_policy_policy.csv');

  // g: alice -> admin -> user, g2: alice -> user
  expect(await e.getNamedImplicitRolesForUser('g', 'alice')).toEqual(['admin', 'user']);
  expect(await e.getNamedImplicitRolesForUser('g2', 'alice')).toEqual(['user']);

  // Each hierarchy is walked on its own and the results are concatenated, so "user" is
  // reported once per role definition that grants it.
  expect(await e.getImplicitRolesForUser('alice')).toEqual(['admin', 'user', 'user']);

  // Following g and then g2 would wrongly hand admin the roles that only alice has via g2.
  expect(await e.getImplicitRolesForUser('admin')).toEqual(['user']);
});

test('test getImplicitRolesForUser with a cycle back to the user', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.addGroupingPolicy('data2_admin', 'alice')).toEqual(true);

  // The user is never reported as one of its own roles.
  expect(await e.getImplicitRolesForUser('alice')).toEqual(['admin', 'data1_admin', 'data2_admin']);
});

test('test getImplicitPermissionsForUser with a wildcard domain in the policy', async () => {
  const e = await newEnforcer(
    'examples/rbac_with_domain_pattern_in_policy_model.conf',
    'examples/rbac_with_domain_pattern_in_policy_policy.csv'
  );
  await e.addNamedDomainMatchingFunc('g', keyMatchFunc);
  await e.buildRoleLinks();

  // The abstract role is reachable in tenant1 only, so nothing leaks into tenant2.
  expect(await e.getImplicitRolesForUser('michael', 'tenant1')).toEqual(['roles1', 'abstract_roles1']);
  expect(await e.getImplicitRolesForUser('michael', 'tenant2')).toEqual([]);

  // Rules stored on the "*" domain are reported for the concrete domain that was asked for.
  expect(await e.getImplicitPermissionsForUser('michael', 'tenant1')).toEqual([
    ['abstract_roles1', 'devis', 'read', 'tenant1', 'allow'],
    ['abstract_roles1', 'devis', 'create', 'tenant1', 'allow'],
    ['roles1', 'devis', 'delete', 'tenant1', 'allow'],
  ]);
  expect(await e.getImplicitPermissionsForUser('michael', 'tenant2')).toEqual([]);

  // A rule bound to tenant1 is not reported for tenant2.
  expect(await e.getImplicitPermissionsForUser('thomas', 'tenant2')).toEqual([
    ['abstract_roles2', 'devis', 'read', 'tenant2', 'allow'],
    ['abstract_roles2', 'organization', 'read', 'tenant2', 'allow'],
    ['abstract_roles2', 'organization', 'write', 'tenant2', 'allow'],
  ]);

  // A role granted on the "*" domain applies to every domain.
  expect(await e.getImplicitPermissionsForUser('theo', 'tenant1')).toEqual([
    ['abstract_roles2', 'devis', 'read', 'tenant1', 'allow'],
    ['abstract_roles2', 'organization', 'read', 'tenant1', 'allow'],
    ['abstract_roles2', 'organization', 'write', 'tenant1', 'allow'],
  ]);

  // getImplicitPermissionsForUser() now agrees with enforce().
  expect(await e.enforce('michael', 'devis', 'read', 'tenant1')).toEqual(true);
  expect(await e.enforce('michael', 'devis', 'read', 'tenant2')).toEqual(false);
  expect(await e.enforce('theo', 'organization', 'write', 'tenant3')).toEqual(true);
});

test('test getNamedImplicitPermissionsForUser', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.getNamedImplicitPermissionsForUser('p', 'g', 'alice')).toEqual([
    ['alice', 'data1', 'read'],
    ['data1_admin', 'data1', 'read'],
    ['data1_admin', 'data1', 'write'],
    ['data2_admin', 'data2', 'read'],
    ['data2_admin', 'data2', 'write'],
  ]);
  expect(await e.getNamedImplicitRolesForUser('g', 'alice')).toEqual(['admin', 'data1_admin', 'data2_admin']);
});

test('test getImplicitResourcesForUser', async () => {
  const e = await newEnforcer('examples/rbac_with_pattern_model.conf', 'examples/rbac_with_pattern_policy.csv');
  expect(await e.getImplicitResourcesForUser('alice')).toEqual([
    ['alice', '/pen/1', 'GET'],
    ['alice', '/pen2/1', 'GET'],
    ['alice', '/book/*', 'GET'],
    ['alice', '/book/:id', 'GET'],
    ['alice', '/book2/{id}', 'GET'],
    ['alice', 'book_group', 'GET'],
  ]);
  expect(await e.getImplicitResourcesForUser('bob')).toEqual([
    ['bob', '/pen/:id', 'GET'],
    ['bob', '/pen2/{id}', 'GET'],
    ['bob', 'pen_group', 'GET'],
  ]);
  expect(await e.getImplicitResourcesForUser('cathy')).toEqual([
    ['cathy', '/pen/:id', 'GET'],
    ['cathy', '/pen2/{id}', 'GET'],
    ['cathy', 'pen_group', 'GET'],
  ]);
});

test('test deleteRolesForUser', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.hasPermissionForUser('bob', 'data2', 'write')).toEqual(true);
  expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
  expect(await e.getImplicitPermissionsForUser('alice')).toEqual([
    ['alice', 'data1', 'read'],
    ['data1_admin', 'data1', 'read'],
    ['data1_admin', 'data1', 'write'],
    ['data2_admin', 'data2', 'read'],
    ['data2_admin', 'data2', 'write'],
  ]);
  expect(await e.deleteRolesForUser('alice')).toEqual(true);
  expect(await e.hasPermissionForUser('alice', 'data1', 'read')).toEqual(true);
  expect(await e.getImplicitPermissionsForUser('alice')).toEqual([['alice', 'data1', 'read']]);
  expect(await e.hasPermissionForUser('bob', 'data2', 'write')).toEqual(true);
  expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
  expect(await e.deleteRolesForUser('bob')).toEqual(false);
  expect(await e.hasPermissionForUser('alice', 'data1', 'read')).toEqual(true);
  expect(await e.getImplicitPermissionsForUser('alice')).toEqual([['alice', 'data1', 'read']]);
  expect(await e.hasPermissionForUser('bob', 'data2', 'write')).toEqual(true);
  expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
});

test('test deleteRolesForUser with domain', async () => {
  const e = await newEnforcer('examples/rbac_with_domains_model.conf', 'examples/rbac_with_domains_policy.csv');
  expect(await e.getImplicitRolesForUser('alice', 'domain1')).toEqual(['admin']);
  expect(await e.getImplicitPermissionsForUser('alice', 'domain1')).toEqual([
    ['admin', 'domain1', 'data1', 'read'],
    ['admin', 'domain1', 'data1', 'write'],
  ]);
  expect(await e.getImplicitPermissionsForUser('bob', 'domain2')).toEqual([
    ['admin', 'domain2', 'data2', 'read'],
    ['admin', 'domain2', 'data2', 'write'],
  ]);
  expect(await e.deleteRolesForUser('alice', 'domain1')).toEqual(true);
  expect(await e.getImplicitRolesForUser('alice', 'domain1')).toEqual([]);
  expect(await e.getImplicitPermissionsForUser('alice', 'domain2')).toEqual([]);
  expect(await e.getImplicitPermissionsForUser('bob', 'domain2')).toEqual([
    ['admin', 'domain2', 'data2', 'read'],
    ['admin', 'domain2', 'data2', 'write'],
  ]);
  expect(await e.deleteRolesForUser('bob', 'domain1')).toEqual(false);
  expect(await e.getImplicitPermissionsForUser('alice', 'domain2')).toEqual([]);
  expect(await e.getImplicitPermissionsForUser('bob', 'domain1')).toEqual([]);
});

test('test deleteRole', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
  expect(await e.getImplicitPermissionsForUser('alice')).toEqual([
    ['alice', 'data1', 'read'],
    ['data1_admin', 'data1', 'read'],
    ['data1_admin', 'data1', 'write'],
    ['data2_admin', 'data2', 'read'],
    ['data2_admin', 'data2', 'write'],
  ]);
  expect(await e.deleteRole('data1_admin')).toEqual(true);
  expect(await e.getImplicitPermissionsForUser('alice')).toEqual([
    ['alice', 'data1', 'read'],
    ['data2_admin', 'data2', 'read'],
    ['data2_admin', 'data2', 'write'],
  ]);
  await e.deleteRole('data2_admin');
  expect(await e.getImplicitPermissionsForUser('alice')).toEqual([['alice', 'data1', 'read']]);
});

test('test deleteUser', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
  expect(await e.getImplicitPermissionsForUser('alice')).toEqual([
    ['alice', 'data1', 'read'],
    ['data1_admin', 'data1', 'read'],
    ['data1_admin', 'data1', 'write'],
    ['data2_admin', 'data2', 'read'],
    ['data2_admin', 'data2', 'write'],
  ]);
  await e.deleteUser('alice');
  expect(await e.getImplicitPermissionsForUser('alice')).toEqual([]);
  expect(await e.getImplicitPermissionsForUser('bob')).toEqual([['bob', 'data2', 'write']]);
  await e.deleteRole('bob');
  expect(await e.getImplicitPermissionsForUser('alice')).toEqual([]);
  expect(await e.getImplicitPermissionsForUser('bob')).toEqual([]);
});

test('test getImplicitUsersForPermission', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.getImplicitUsersForPermission('data1', 'read')).toEqual(['alice']);
  expect(await e.getImplicitUsersForPermission('data1', 'write')).toEqual(['alice']);
  expect(await e.getImplicitUsersForPermission('data2', 'read')).toEqual(['alice']);
  expect(await e.getImplicitUsersForPermission('data2', 'write')).toEqual(['alice', 'bob']);

  e.clearPolicy();

  await e.addPolicy('admin', 'data1', 'read');
  await e.addPolicy('bob', 'data1', 'read');
  await e.addGroupingPolicy('alice', 'admin');

  expect(await e.getImplicitUsersForPermission('data1', 'read')).toEqual(['bob', 'alice']);
});

test('test getImplicitUsersForRole', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  expect(await e.getImplicitUsersForRole('admin')).toEqual(['alice']);
  expect(await e.getImplicitUsersForRole('data1_admin')).toEqual(['admin', 'alice']);
});

test('test rbac with multiple policy definitions', async () => {
  const e = await newEnforcer('examples/rbac_with_multiple_policy_model.conf', 'examples/rbac_with_multiple_policy_policy.csv');

  // Test getting named policies for different policy types
  const pPolicies = await e.getNamedPolicy('p');
  expect(pPolicies).toEqual([
    ['user', '/data', 'GET'],
    ['admin', '/data', 'POST'],
  ]);

  const p2Policies = await e.getNamedPolicy('p2');
  expect(p2Policies).toEqual([
    ['user', 'view'],
    ['admin', 'create'],
  ]);
});

test('test deleteUser with empty string should throw error', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');

  // Store initial state
  const initialGPolicies = await e.getGroupingPolicy();
  const initialPPolicies = await e.getPolicy();
  expect(initialGPolicies.length).toBeGreaterThan(0);
  expect(initialPPolicies.length).toBeGreaterThan(0);

  // Attempt to delete with empty string should throw
  await expect(e.deleteUser('')).rejects.toThrow('user must not be empty');

  // Verify nothing was deleted
  expect(await e.getGroupingPolicy()).toEqual(initialGPolicies);
  expect(await e.getPolicy()).toEqual(initialPPolicies);
});

test('test deleteRole with empty string should throw error', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');

  const initialGPolicies = await e.getGroupingPolicy();
  const initialPPolicies = await e.getPolicy();
  expect(initialGPolicies.length).toBeGreaterThan(0);
  expect(initialPPolicies.length).toBeGreaterThan(0);

  await expect(e.deleteRole('')).rejects.toThrow('role must not be empty');

  expect(await e.getGroupingPolicy()).toEqual(initialGPolicies);
  expect(await e.getPolicy()).toEqual(initialPPolicies);
});

test('test deletePermissionsForUser with empty string should throw error', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');

  const initialPPolicies = await e.getPolicy();
  expect(initialPPolicies.length).toBeGreaterThan(0);

  await expect(e.deletePermissionsForUser('')).rejects.toThrow('user must not be empty');

  expect(await e.getPolicy()).toEqual(initialPPolicies);
});

test('test deleteRolesForUser with empty string should throw error', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');

  const initialGPolicies = await e.getGroupingPolicy();
  expect(initialGPolicies.length).toBeGreaterThan(0);

  await expect(e.deleteRolesForUser('')).rejects.toThrow('user must not be empty');

  expect(await e.getGroupingPolicy()).toEqual(initialGPolicies);
});

test('test deleteRoleForUser with empty strings should throw error', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');

  await expect(e.deleteRoleForUser('', 'admin')).rejects.toThrow('user must not be empty');
  await expect(e.deleteRoleForUser('alice', '')).rejects.toThrow('role must not be empty');
  await expect(e.deleteRoleForUser('', '')).rejects.toThrow('user must not be empty');
});

test('test deletePermissionForUser with empty string should throw error', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');

  await expect(e.deletePermissionForUser('', 'data1', 'read')).rejects.toThrow('user must not be empty');
});

test('test deletePermission with empty array should throw error', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');

  const initialPPolicies = await e.getPolicy();
  expect(initialPPolicies.length).toBeGreaterThan(0);

  await expect(e.deletePermission()).rejects.toThrow('permission must not be empty');

  expect(await e.getPolicy()).toEqual(initialPPolicies);
});
