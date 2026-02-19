import * as benchmark from 'benchmark';
import * as path from 'path';
import { CachedEnforcer, newCachedEnforcer } from '../src';

// Helper to resolve paths
const resolve = (p: string): string => path.join(__dirname, '..', p);

// Helper to generate RBAC policies (Short names: group%d)
async function generateRBAC(e: CachedEnforcer, roles: number, users: number): Promise<void> {
  const pPolicies = [];
  for (let i = 0; i < roles; i++) {
    pPolicies.push([`group${i}`, `data${Math.floor(i / 10)}`, 'read']);
  }
  if (pPolicies.length > 0) {
    await e.addPolicies(pPolicies);
  }

  const gPolicies = [];
  for (let i = 0; i < users; i++) {
    gPolicies.push([`user${i}`, `group${Math.floor(i / 10)}`]);
  }
  if (gPolicies.length > 0) {
    await e.addGroupingPolicies(gPolicies);
  }
}

export async function addCachedEnforcerBenchmarks(suite: benchmark.Suite): Promise<void> {
  // BenchmarkCachedBasicModel
  const eBasic = await newCachedEnforcer(resolve('examples/basic_model.conf'), resolve('examples/basic_policy.csv'));
  eBasic.enableLog(false);
  suite.add('BenchmarkCachedBasicModel', {
    defer: true,
    fn: async (deferred: any) => {
      await eBasic.enforce('alice', 'data1', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkCachedRBACModel
  const eRBAC = await newCachedEnforcer(resolve('examples/rbac_model.conf'), resolve('examples/rbac_policy.csv'));
  eRBAC.enableLog(false);
  suite.add('BenchmarkCachedRBACModel', {
    defer: true,
    fn: async (deferred: any) => {
      await eRBAC.enforce('alice', 'data2', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkCachedRBACModelSmall
  const eSmall = await newCachedEnforcer(resolve('examples/rbac_model.conf'));
  eSmall.enableLog(false);
  await generateRBAC(eSmall, 100, 1000);
  suite.add('BenchmarkCachedRBACModelSmall', {
    defer: true,
    fn: async (deferred: any) => {
      await eSmall.enforce('user501', 'data9', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkCachedRBACModelMedium
  const eMedium = await newCachedEnforcer(resolve('examples/rbac_model.conf'));
  eMedium.enableLog(false);
  await generateRBAC(eMedium, 1000, 10000);
  suite.add('BenchmarkCachedRBACModelMedium', {
    defer: true,
    fn: async (deferred: any) => {
      await eMedium.enforce('user5001', 'data150', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkCachedRBACModelLarge
  const eLarge = await newCachedEnforcer(resolve('examples/rbac_model.conf'));
  eLarge.enableLog(false);
  await generateRBAC(eLarge, 10000, 100000);
  suite.add('BenchmarkCachedRBACModelLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await eLarge.enforce('user50001', 'data1500', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkCachedRBACModelWithResourceRoles
  const eResRoles = await newCachedEnforcer(
    resolve('examples/rbac_with_resource_roles_model.conf'),
    resolve('examples/rbac_with_resource_roles_policy.csv')
  );
  eResRoles.enableLog(false);
  suite.add('BenchmarkCachedRBACModelWithResourceRoles', {
    defer: true,
    fn: async (deferred: any) => {
      await eResRoles.enforce('alice', 'data1', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkCachedRBACModelWithDomains
  const eDomains = await newCachedEnforcer(
    resolve('examples/rbac_with_domains_model.conf'),
    resolve('examples/rbac_with_domains_policy.csv')
  );
  eDomains.enableLog(false);
  suite.add('BenchmarkCachedRBACModelWithDomains', {
    defer: true,
    fn: async (deferred: any) => {
      await eDomains.enforce('alice', 'domain1', 'data1', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkCachedABACModel
  const eABAC = await newCachedEnforcer(resolve('examples/abac_model.conf'));
  eABAC.enableLog(false);
  const abacData1 = { Name: 'data1', Owner: 'alice' };
  suite.add('BenchmarkCachedABACModel', {
    defer: true,
    fn: async (deferred: any) => {
      await eABAC.enforce('alice', abacData1, 'read');
      deferred.resolve();
    },
  });

  // BenchmarkCachedKeyMatchModel
  const eKeyMatch = await newCachedEnforcer(resolve('examples/keymatch_model.conf'), resolve('examples/keymatch_policy.csv'));
  eKeyMatch.enableLog(false);
  suite.add('BenchmarkCachedKeyMatchModel', {
    defer: true,
    fn: async (deferred: any) => {
      await eKeyMatch.enforce('alice', '/alice_data/resource1', 'GET');
      deferred.resolve();
    },
  });

  // BenchmarkCachedRBACModelWithDeny
  const eDeny = await newCachedEnforcer(resolve('examples/rbac_with_deny_model.conf'), resolve('examples/rbac_with_deny_policy.csv'));
  eDeny.enableLog(false);
  suite.add('BenchmarkCachedRBACModelWithDeny', {
    defer: true,
    fn: async (deferred: any) => {
      await eDeny.enforce('alice', 'data1', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkCachedPriorityModel
  const ePriority = await newCachedEnforcer(resolve('examples/priority_model.conf'), resolve('examples/priority_policy.csv'));
  ePriority.enableLog(false);
  suite.add('BenchmarkCachedPriorityModel', {
    defer: true,
    fn: async (deferred: any) => {
      await ePriority.enforce('alice', 'data1', 'read');
      deferred.resolve();
    },
  });
}
