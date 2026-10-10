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

import { newEnforcer, Enforcer } from '../src';

interface SpyAdapter {
  loadPolicy: jest.Mock<Promise<boolean>, any[]>;
  addPolicy: jest.Mock;
  removePolicy: jest.Mock;
  updatePolicy: jest.Mock;
  removeFilteredPolicy: jest.Mock;
  addPolicies: jest.Mock;
  removePolicies: jest.Mock;
  updatePolicies: jest.Mock;
  savePolicy: jest.Mock;
}

function createSpyAdapter(): SpyAdapter {
  return {
    loadPolicy: jest.fn(async () => true),
    addPolicy: jest.fn(async () => true),
    removePolicy: jest.fn(async () => true),
    updatePolicy: jest.fn(async () => true),
    removeFilteredPolicy: jest.fn(async () => true),
    addPolicies: jest.fn(async () => true),
    removePolicies: jest.fn(async () => true),
    updatePolicies: jest.fn(async () => true),
    savePolicy: jest.fn(async () => true),
  };
}

describe('Management self* APIs bypass adapter and update memory', () => {
  let e: Enforcer;
  let adapter: SpyAdapter;

  beforeEach(async () => {
    adapter = createSpyAdapter();
    e = (await newEnforcer('examples/basic_model.conf', adapter as any)) as Enforcer;
    e.enableAutoSave(true);
  });

  test('selfAddPolicy adds to memory and skips adapter', async () => {
    const rule = ['alice', 'data1', 'read'];

    const added = await e.selfAddPolicy('p', 'p', rule);

    expect(added).toBe(true);
    expect(await e.hasPolicy(...rule)).toBe(true);
    expect(adapter.addPolicy).not.toHaveBeenCalled();
  });

  test('selfRemovePolicy removes from memory and skips adapter', async () => {
    const rule = ['bob', 'data2', 'write'];
    await e.selfAddPolicy('p', 'p', rule);

    const removed = await e.selfRemovePolicy('p', 'p', rule);

    expect(removed).toBe(true);
    expect(await e.hasPolicy(...rule)).toBe(false);
    expect(adapter.removePolicy).not.toHaveBeenCalled();
  });

  test('selfUpdatePolicy updates in memory and skips adapter', async () => {
    const oldRule = ['carol', 'data3', 'read'];
    const newRule = ['carol', 'data3', 'write'];
    await e.selfAddPolicy('p', 'p', oldRule);

    const updated = await e.selfUpdatePolicy('p', 'p', oldRule, newRule);

    expect(updated).toBe(true);
    expect(await e.hasPolicy(...oldRule)).toBe(false);
    expect(await e.hasPolicy(...newRule)).toBe(true);
    expect(adapter.updatePolicy).not.toHaveBeenCalled();
  });

  test('selfAddPolicies and selfRemovePolicies work in memory only', async () => {
    const rules = [
      ['dave', 'data4', 'read'],
      ['erin', 'data5', 'write'],
    ];

    const added = await e.selfAddPolicies('p', 'p', rules);
    expect(added).toBe(true);
    expect(await e.hasPolicy(...rules[0])).toBe(true);
    expect(await e.hasPolicy(...rules[1])).toBe(true);
    expect(adapter.addPolicies).not.toHaveBeenCalled();

    const removed = await e.selfRemovePolicies('p', 'p', rules);
    expect(removed).toBe(true);
    expect(await e.hasPolicy(...rules[0])).toBe(false);
    expect(await e.hasPolicy(...rules[1])).toBe(false);
    expect(adapter.removePolicies).not.toHaveBeenCalled();
  });

  test('selfRemoveFilteredPolicy removes matching rules without adapter', async () => {
    await e.selfAddPolicy('p', 'p', ['frank', 'data6', 'read']);
    await e.selfAddPolicy('p', 'p', ['frank', 'data7', 'write']);

    const removed = await e.selfRemoveFilteredPolicy('p', 'p', 0, 'frank');

    expect(removed).toBe(true);
    expect(await e.hasPolicy('frank', 'data6', 'read')).toBe(false);
    expect(await e.hasPolicy('frank', 'data7', 'write')).toBe(false);
    expect(adapter.removeFilteredPolicy).not.toHaveBeenCalled();
  });

  test('selfUpdatePolicies updates multiple rules in memory', async () => {
    const oldRules = [
      ['gina', 'data8', 'read'],
      ['harry', 'data9', 'read'],
    ];
    const newRules = [
      ['gina', 'data8', 'write'],
      ['harry', 'data9', 'write'],
    ];

    await e.selfAddPolicies('p', 'p', oldRules);
    const updated = await e.selfUpdatePolicies('p', 'p', oldRules, newRules);

    expect(updated).toBe(true);
    expect(await e.hasPolicy('gina', 'data8', 'write')).toBe(true);
    expect(await e.hasPolicy('harry', 'data9', 'write')).toBe(true);
    expect(await e.hasPolicy('gina', 'data8', 'read')).toBe(false);
    expect(await e.hasPolicy('harry', 'data9', 'read')).toBe(false);
    expect(adapter.updatePolicies).not.toHaveBeenCalled();
  });

  test('selfAddPolicy returns false when policy already exists', async () => {
    const rule = ['ivy', 'data10', 'read'];
    await e.selfAddPolicy('p', 'p', rule);

    const added = await e.selfAddPolicy('p', 'p', rule);

    expect(added).toBe(false);
  });

  test('selfRemovePolicy returns false when policy does not exist', async () => {
    const rule = ['nonexistent', 'data11', 'read'];

    const removed = await e.selfRemovePolicy('p', 'p', rule);

    expect(removed).toBe(false);
  });

  test('selfUpdatePolicy returns false when old policy does not exist', async () => {
    const oldRule = ['nonexistent', 'data12', 'read'];
    const newRule = ['nonexistent', 'data12', 'write'];

    const updated = await e.selfUpdatePolicy('p', 'p', oldRule, newRule);

    expect(updated).toBe(false);
  });

  test('selfAddPolicies returns false when any policy already exists', async () => {
    const rule1 = ['jack', 'data13', 'read'];
    await e.selfAddPolicy('p', 'p', rule1);

    const rules = [rule1, ['karen', 'data14', 'write']];

    const added = await e.selfAddPolicies('p', 'p', rules);

    expect(added).toBe(false);
  });

  test('selfRemovePolicies returns false when any policy does not exist', async () => {
    const rule1 = ['leo', 'data15', 'read'];
    await e.selfAddPolicy('p', 'p', rule1);

    const rules = [rule1, ['nonexistent', 'data16', 'write']];

    const removed = await e.selfRemovePolicies('p', 'p', rules);

    expect(removed).toBe(false);
  });

  test('selfUpdatePolicies throws error when array lengths mismatch', async () => {
    const oldRules = [['mia', 'data17', 'read']];
    const newRules = [
      ['mia', 'data17', 'write'],
      ['nancy', 'data18', 'read'],
    ];

    await expect(e.selfUpdatePolicies('p', 'p', oldRules, newRules)).rejects.toThrow(
      'the length of oldRules should be equal to the length of newRules'
    );
  });

  test('selfUpdatePolicies returns false when any old policy does not exist', async () => {
    const oldRules = [
      ['oscar', 'data19', 'read'],
      ['nonexistent', 'data20', 'read'],
    ];
    const newRules = [
      ['oscar', 'data19', 'write'],
      ['nonexistent', 'data20', 'write'],
    ];
    await e.selfAddPolicy('p', 'p', oldRules[0]);

    const updated = await e.selfUpdatePolicies('p', 'p', oldRules, newRules);

    expect(updated).toBe(false);
  });
});

describe('Management self* APIs with grouping policies', () => {
  let e: Enforcer;
  let adapter: SpyAdapter;

  beforeEach(async () => {
    adapter = createSpyAdapter();
    e = (await newEnforcer('examples/rbac_model.conf', adapter as any)) as Enforcer;
    e.enableAutoSave(true);
  });

  test('selfAddPolicy works with g section for role links', async () => {
    const rule = ['alice', 'admin'];

    const added = await e.selfAddPolicy('g', 'g', rule);

    expect(added).toBe(true);
    expect(adapter.addPolicy).not.toHaveBeenCalled();
  });

  test('selfRemovePolicy works with g section for role links', async () => {
    const rule = ['bob', 'editor'];
    await e.selfAddPolicy('g', 'g', rule);

    const removed = await e.selfRemovePolicy('g', 'g', rule);

    expect(removed).toBe(true);
    expect(adapter.removePolicy).not.toHaveBeenCalled();
  });

  test('selfUpdatePolicy works with g section for role links', async () => {
    const oldRule = ['carol', 'viewer'];
    const newRule = ['carol', 'editor'];
    await e.selfAddPolicy('g', 'g', oldRule);

    const updated = await e.selfUpdatePolicy('g', 'g', oldRule, newRule);

    expect(updated).toBe(true);
    expect(adapter.updatePolicy).not.toHaveBeenCalled();
  });

  test('selfAddPolicies works with multiple g policies', async () => {
    const rules = [
      ['dave', 'admin'],
      ['eve', 'editor'],
    ];

    const added = await e.selfAddPolicies('g', 'g', rules);

    expect(added).toBe(true);
    expect(adapter.addPolicies).not.toHaveBeenCalled();
  });

  test('selfRemoveFilteredPolicy works with g section', async () => {
    await e.selfAddPolicy('g', 'g', ['frank', 'admin']);
    await e.selfAddPolicy('g', 'g', ['frank', 'editor']);

    const removed = await e.selfRemoveFilteredPolicy('g', 'g', 0, 'frank');

    expect(removed).toBe(true);
    expect(adapter.removeFilteredPolicy).not.toHaveBeenCalled();
  });
});
