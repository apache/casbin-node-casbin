import * as benchmark from 'benchmark';
import * as path from 'path';
import { Enforcer, newEnforcer, Util } from '../src';

// Helper to resolve paths
const resolve = (p: string): string => path.join(__dirname, '..', p);

// Helper to generate RBAC policies (Short names: group%d)
async function generateRBAC(e: Enforcer, roles: number, users: number): Promise<void> {
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

// Helper to generate RBAC policies (Long names: group-has-a-very-long-name-%d)
async function generateRBACLong(e: Enforcer, roles: number, resources: number, users: number): Promise<void> {
  const pPolicies = [];
  for (let i = 0; i < roles; i++) {
    pPolicies.push([`group-has-a-very-long-name-${i}`, `data-has-a-very-long-name-${i % resources}`, 'read']);
  }
  if (pPolicies.length > 0) {
    await e.addPolicies(pPolicies);
  }

  const gPolicies = [];
  for (let i = 0; i < users; i++) {
    gPolicies.push([`user-has-a-very-long-name-${i}`, `group-has-a-very-long-name-${i % roles}`]);
  }
  if (gPolicies.length > 0) {
    await e.addGroupingPolicies(gPolicies);
  }
}

// Helper to get enforcement params for Long names
function getEnforcementsLong(users: number, roles: number, resources: number): string[][] {
  const enforcements = [];
  for (let i = 0; i < 17; i++) {
    const userNum = Math.floor((users / 17) * i);
    const roleNum = userNum % roles;
    let resourceNum = roleNum % resources;
    if (i % 2 === 0) {
      resourceNum = (resourceNum + 1) % resources;
    }
    enforcements.push([`user-has-a-very-long-name-${userNum}`, `data-has-a-very-long-name-${resourceNum}`, 'read']);
  }
  return enforcements;
}

export async function addEnforcerBenchmarks(suite: benchmark.Suite): Promise<void> {
  // BenchmarkBasicModel
  const eBasic = await newEnforcer(resolve('examples/basic_model.conf'), resolve('examples/basic_policy.csv'));
  eBasic.enableLog(false);
  suite.add('BenchmarkBasicModel', {
    defer: true,
    fn: async (deferred: any) => {
      await eBasic.enforce('alice', 'data1', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkRBACModel
  const eRBAC = await newEnforcer(resolve('examples/rbac_model.conf'), resolve('examples/rbac_policy.csv'));
  eRBAC.enableLog(false);
  suite.add('BenchmarkRBACModel', {
    defer: true,
    fn: async (deferred: any) => {
      await eRBAC.enforce('alice', 'data2', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkRBACModelSizes (Small)
  const eSizesSmall = await newEnforcer(resolve('examples/rbac_model.conf'));
  eSizesSmall.enableLog(false);
  await generateRBACLong(eSizesSmall, 100, 10, 1000);
  const enfSizesSmall = getEnforcementsLong(1000, 100, 10);
  let idxSmall = 0;
  suite.add('BenchmarkRBACModelSizesSmall', {
    defer: true,
    fn: async (deferred: any) => {
      await eSizesSmall.enforce(...enfSizesSmall[idxSmall % 17]);
      idxSmall++;
      deferred.resolve();
    },
  });

  // BenchmarkRBACModelSizes (Medium)
  const eSizesMedium = await newEnforcer(resolve('examples/rbac_model.conf'));
  eSizesMedium.enableLog(false);
  await generateRBACLong(eSizesMedium, 1000, 100, 10000);
  const enfSizesMedium = getEnforcementsLong(10000, 1000, 100);
  let idxMedium = 0;
  suite.add('BenchmarkRBACModelSizesMedium', {
    defer: true,
    fn: async (deferred: any) => {
      await eSizesMedium.enforce(...enfSizesMedium[idxMedium % 17]);
      idxMedium++;
      deferred.resolve();
    },
  });

  // BenchmarkRBACModelSizes (Large)
  const eSizesLarge = await newEnforcer(resolve('examples/rbac_model.conf'));
  eSizesLarge.enableLog(false);
  await generateRBACLong(eSizesLarge, 10000, 1000, 100000);
  const enfSizesLarge = getEnforcementsLong(100000, 10000, 1000);
  let idxLarge = 0;
  suite.add('BenchmarkRBACModelSizesLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await eSizesLarge.enforce(...enfSizesLarge[idxLarge % 17]);
      idxLarge++;
      deferred.resolve();
    },
  });

  // BenchmarkRBACModelSmall (Short names)
  const eSmall = await newEnforcer(resolve('examples/rbac_model.conf'));
  eSmall.enableLog(false);
  await generateRBAC(eSmall, 100, 1000);
  suite.add('BenchmarkRBACModelSmall', {
    defer: true,
    fn: async (deferred: any) => {
      await eSmall.enforce('user501', 'data9', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkRBACModelMedium (Short names)
  const eMedium = await newEnforcer(resolve('examples/rbac_model.conf'));
  eMedium.enableLog(false);
  await generateRBAC(eMedium, 1000, 10000);
  suite.add('BenchmarkRBACModelMedium', {
    defer: true,
    fn: async (deferred: any) => {
      await eMedium.enforce('user5001', 'data99', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkRBACModelLarge (Short names)
  const eLarge = await newEnforcer(resolve('examples/rbac_model.conf'));
  eLarge.enableLog(false);
  await generateRBAC(eLarge, 10000, 100000);
  suite.add('BenchmarkRBACModelLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await eLarge.enforce('user50001', 'data999', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkRBACModelWithResourceRoles
  const eResRoles = await newEnforcer(
    resolve('examples/rbac_with_resource_roles_model.conf'),
    resolve('examples/rbac_with_resource_roles_policy.csv')
  );
  eResRoles.enableLog(false);
  suite.add('BenchmarkRBACModelWithResourceRoles', {
    defer: true,
    fn: async (deferred: any) => {
      await eResRoles.enforce('alice', 'data1', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkRBACModelWithDomains
  const eDomains = await newEnforcer(resolve('examples/rbac_with_domains_model.conf'), resolve('examples/rbac_with_domains_policy.csv'));
  eDomains.enableLog(false);
  suite.add('BenchmarkRBACModelWithDomains', {
    defer: true,
    fn: async (deferred: any) => {
      await eDomains.enforce('alice', 'domain1', 'data1', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkABACModel
  const eABAC = await newEnforcer(resolve('examples/abac_model.conf'));
  eABAC.enableLog(false);
  const abacData1 = { Name: 'data1', Owner: 'alice' };
  suite.add('BenchmarkABACModel', {
    defer: true,
    fn: async (deferred: any) => {
      await eABAC.enforce('alice', abacData1, 'read');
      deferred.resolve();
    },
  });

  // BenchmarkABACRuleModel
  const eABACRule = await newEnforcer(resolve('examples/abac_rule_model.conf'));
  eABACRule.enableLog(false);
  const abacSub = { Name: 'alice', Age: 18 };
  for (let i = 0; i < 1000; i++) {
    await eABACRule.addPolicy('r.sub.Age > 20', `data${i}`, 'read');
  }
  suite.add('BenchmarkABACRuleModel', {
    defer: true,
    fn: async (deferred: any) => {
      await eABACRule.enforce(abacSub, 'data100', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkKeyMatchModel
  const eKeyMatch = await newEnforcer(resolve('examples/keymatch_model.conf'), resolve('examples/keymatch_policy.csv'));
  eKeyMatch.enableLog(false);
  suite.add('BenchmarkKeyMatchModel', {
    defer: true,
    fn: async (deferred: any) => {
      await eKeyMatch.enforce('alice', '/alice_data/resource1', 'GET');
      deferred.resolve();
    },
  });

  // BenchmarkRBACModelWithDeny
  const eDeny = await newEnforcer(resolve('examples/rbac_with_deny_model.conf'), resolve('examples/rbac_with_deny_policy.csv'));
  eDeny.enableLog(false);
  suite.add('BenchmarkRBACModelWithDeny', {
    defer: true,
    fn: async (deferred: any) => {
      await eDeny.enforce('alice', 'data1', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkPriorityModel
  const ePriority = await newEnforcer(resolve('examples/priority_model.conf'), resolve('examples/priority_policy.csv'));
  ePriority.enableLog(false);
  suite.add('BenchmarkPriorityModel', {
    defer: true,
    fn: async (deferred: any) => {
      await ePriority.enforce('alice', 'data1', 'read');
      deferred.resolve();
    },
  });

  // BenchmarkRBACModelWithDomainPatternLarge
  const ePatternLarge = await newEnforcer(
    resolve('examples/performance/rbac_with_pattern_large_scale_model.conf'),
    resolve('examples/performance/rbac_with_pattern_large_scale_policy.csv')
  );
  ePatternLarge.enableLog(false);
  ePatternLarge.addNamedDomainMatchingFunc('g', Util.keyMatch4Func);
  await ePatternLarge.buildRoleLinks();
  suite.add('BenchmarkRBACModelWithDomainPatternLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await ePatternLarge.enforce('staffUser1001', '/orgs/1/sites/site001', 'App001.Module001.Action1001');
      deferred.resolve();
    },
  });
}
