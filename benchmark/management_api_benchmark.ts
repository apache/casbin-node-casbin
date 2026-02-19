import * as benchmark from 'benchmark';
import * as path from 'path';
import { newEnforcer } from '../src';

// Helper to resolve paths
const resolve = (p: string): string => path.join(__dirname, '..', p);

export async function addManagementApiBenchmarks(suite: benchmark.Suite): Promise<void> {
  // BenchmarkHasPolicySmall
  const eHasSmall = await newEnforcer(resolve('examples/basic_model.conf'));
  eHasSmall.enableLog(false);
  for (let i = 0; i < 100; i++) {
    await eHasSmall.addPolicy(`user${i}`, `data${Math.floor(i / 10)}`, 'read');
  }
  suite.add('BenchmarkHasPolicySmall', {
    defer: true,
    fn: async (deferred: any) => {
      await eHasSmall.hasPolicy(
        `user${Math.floor(Math.random() * 100)}`,
        `data${Math.floor(Math.floor(Math.random() * 100) / 10)}`,
        'read'
      );
      deferred.resolve();
    },
  });

  // BenchmarkHasPolicyMedium
  const eHasMedium = await newEnforcer(resolve('examples/basic_model.conf'));
  eHasMedium.enableLog(false);
  const pPoliciesMedium = [];
  for (let i = 0; i < 1000; i++) {
    pPoliciesMedium.push([`user${i}`, `data${Math.floor(i / 10)}`, 'read']);
  }
  await eHasMedium.addPolicies(pPoliciesMedium);
  suite.add('BenchmarkHasPolicyMedium', {
    defer: true,
    fn: async (deferred: any) => {
      await eHasMedium.hasPolicy(
        `user${Math.floor(Math.random() * 1000)}`,
        `data${Math.floor(Math.floor(Math.random() * 1000) / 10)}`,
        'read'
      );
      deferred.resolve();
    },
  });

  // BenchmarkHasPolicyLarge
  const eHasLarge = await newEnforcer(resolve('examples/basic_model.conf'));
  eHasLarge.enableLog(false);
  const pPoliciesLarge = [];
  for (let i = 0; i < 10000; i++) {
    pPoliciesLarge.push([`user${i}`, `data${Math.floor(i / 10)}`, 'read']);
  }
  await eHasLarge.addPolicies(pPoliciesLarge);
  suite.add('BenchmarkHasPolicyLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await eHasLarge.hasPolicy(
        `user${Math.floor(Math.random() * 10000)}`,
        `data${Math.floor(Math.floor(Math.random() * 10000) / 10)}`,
        'read'
      );
      deferred.resolve();
    },
  });

  // BenchmarkAddPolicySmall
  const eAddSmall = await newEnforcer(resolve('examples/basic_model.conf'));
  eAddSmall.enableLog(false);
  for (let i = 0; i < 100; i++) {
    await eAddSmall.addPolicy(`user${i}`, `data${Math.floor(i / 10)}`, 'read');
  }
  suite.add('BenchmarkAddPolicySmall', {
    defer: true,
    fn: async (deferred: any) => {
      const randVal = Math.floor(Math.random() * 100) + 100;
      await eAddSmall.addPolicy(`user${randVal}`, `data${Math.floor(randVal / 10)}`, 'read');
      deferred.resolve();
    },
  });

  // BenchmarkAddPolicyMedium
  const eAddMedium = await newEnforcer(resolve('examples/basic_model.conf'));
  eAddMedium.enableLog(false);
  const pPoliciesAddMedium = [];
  for (let i = 0; i < 1000; i++) {
    pPoliciesAddMedium.push([`user${i}`, `data${Math.floor(i / 10)}`, 'read']);
  }
  await eAddMedium.addPolicies(pPoliciesAddMedium);
  suite.add('BenchmarkAddPolicyMedium', {
    defer: true,
    fn: async (deferred: any) => {
      const randVal = Math.floor(Math.random() * 1000) + 1000;
      await eAddMedium.addPolicy(`user${randVal}`, `data${Math.floor(randVal / 10)}`, 'read');
      deferred.resolve();
    },
  });

  // BenchmarkAddPolicyLarge
  const eAddLarge = await newEnforcer(resolve('examples/basic_model.conf'));
  eAddLarge.enableLog(false);
  const pPoliciesAddLarge = [];
  for (let i = 0; i < 10000; i++) {
    pPoliciesAddLarge.push([`user${i}`, `data${Math.floor(i / 10)}`, 'read']);
  }
  await eAddLarge.addPolicies(pPoliciesAddLarge);
  suite.add('BenchmarkAddPolicyLarge', {
    defer: true,
    fn: async (deferred: any) => {
      const randVal = Math.floor(Math.random() * 10000) + 10000;
      await eAddLarge.addPolicy(`user${randVal}`, `data${Math.floor(randVal / 10)}`, 'read');
      deferred.resolve();
    },
  });

  // BenchmarkRemovePolicySmall
  const eRemoveSmall = await newEnforcer(resolve('examples/basic_model.conf'));
  eRemoveSmall.enableLog(false);
  for (let i = 0; i < 100; i++) {
    await eRemoveSmall.addPolicy(`user${i}`, `data${Math.floor(i / 10)}`, 'read');
  }
  suite.add('BenchmarkRemovePolicySmall', {
    defer: true,
    fn: async (deferred: any) => {
      const randVal = Math.floor(Math.random() * 100);
      await eRemoveSmall.removePolicy(`user${randVal}`, `data${Math.floor(randVal / 10)}`, 'read');
      deferred.resolve();
    },
  });

  // BenchmarkRemovePolicyMedium
  const eRemoveMedium = await newEnforcer(resolve('examples/basic_model.conf'));
  eRemoveMedium.enableLog(false);
  const pPoliciesRemoveMedium = [];
  for (let i = 0; i < 1000; i++) {
    pPoliciesRemoveMedium.push([`user${i}`, `data${Math.floor(i / 10)}`, 'read']);
  }
  await eRemoveMedium.addPolicies(pPoliciesRemoveMedium);
  suite.add('BenchmarkRemovePolicyMedium', {
    defer: true,
    fn: async (deferred: any) => {
      const randVal = Math.floor(Math.random() * 1000);
      await eRemoveMedium.removePolicy(`user${randVal}`, `data${Math.floor(randVal / 10)}`, 'read');
      deferred.resolve();
    },
  });

  // BenchmarkRemovePolicyLarge
  const eRemoveLarge = await newEnforcer(resolve('examples/basic_model.conf'));
  eRemoveLarge.enableLog(false);
  const pPoliciesRemoveLarge = [];
  for (let i = 0; i < 10000; i++) {
    pPoliciesRemoveLarge.push([`user${i}`, `data${Math.floor(i / 10)}`, 'read']);
  }
  await eRemoveLarge.addPolicies(pPoliciesRemoveLarge);
  suite.add('BenchmarkRemovePolicyLarge', {
    defer: true,
    fn: async (deferred: any) => {
      const randVal = Math.floor(Math.random() * 10000);
      await eRemoveLarge.removePolicy(`user${randVal}`, `data${Math.floor(randVal / 10)}`, 'read');
      deferred.resolve();
    },
  });
}
