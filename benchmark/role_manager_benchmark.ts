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

export async function addRoleManagerBenchmarks(suite: benchmark.Suite): Promise<void> {
  // BenchmarkRoleManagerSmall
  const eSmall = await newEnforcer(resolve('examples/rbac_model.conf'));
  eSmall.enableLog(false);
  eSmall.enableAutoBuildRoleLinks(false);
  await generateRBAC(eSmall, 100, 1000);
  const rmSmall = eSmall.getRoleManager();
  suite.add('BenchmarkRoleManagerSmall', {
    defer: true,
    fn: async (deferred: any) => {
      for (let j = 0; j < 100; j++) {
        await rmSmall.hasLink('user501', `group${j}`);
      }
      deferred.resolve();
    },
  });

  // BenchmarkRoleManagerMedium
  const eMedium = await newEnforcer(resolve('examples/rbac_model.conf'));
  eMedium.enableLog(false);
  eMedium.enableAutoBuildRoleLinks(false);
  await generateRBAC(eMedium, 1000, 10000);
  await eMedium.buildRoleLinks();
  const rmMedium = eMedium.getRoleManager();
  suite.add('BenchmarkRoleManagerMedium', {
    defer: true,
    fn: async (deferred: any) => {
      for (let j = 0; j < 1000; j++) {
        await rmMedium.hasLink('user501', `group${j}`);
      }
      deferred.resolve();
    },
  });

  // BenchmarkRoleManagerLarge
  const eLarge = await newEnforcer(resolve('examples/rbac_model.conf'));
  eLarge.enableLog(false);
  await generateRBAC(eLarge, 10000, 100000);
  const rmLarge = eLarge.getRoleManager();
  suite.add('BenchmarkRoleManagerLarge', {
    defer: true,
    fn: async (deferred: any) => {
      for (let j = 0; j < 10000; j++) {
        await rmLarge.hasLink('user501', `group${j}`);
      }
      deferred.resolve();
    },
  });

  // BenchmarkBuildRoleLinksWithPatternLarge
  const ePattern = await newEnforcer(
    resolve('examples/performance/rbac_with_pattern_large_scale_model.conf'),
    resolve('examples/performance/rbac_with_pattern_large_scale_policy.csv')
  );
  ePattern.enableLog(false);
  ePattern.addNamedMatchingFunc('g', Util.keyMatch4Func);
  suite.add('BenchmarkBuildRoleLinksWithPatternLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await ePattern.buildRoleLinks();
      deferred.resolve();
    },
  });

  // BenchmarkBuildRoleLinksWithDomainPatternLarge
  const eDomainPattern = await newEnforcer(
    resolve('examples/performance/rbac_with_pattern_large_scale_model.conf'),
    resolve('examples/performance/rbac_with_pattern_large_scale_policy.csv')
  );
  eDomainPattern.enableLog(false);
  eDomainPattern.addNamedDomainMatchingFunc('g', Util.keyMatch4Func);
  suite.add('BenchmarkBuildRoleLinksWithDomainPatternLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await eDomainPattern.buildRoleLinks();
      deferred.resolve();
    },
  });

  // BenchmarkBuildRoleLinksWithPatternAndDomainPatternLarge
  const eBoth = await newEnforcer(
    resolve('examples/performance/rbac_with_pattern_large_scale_model.conf'),
    resolve('examples/performance/rbac_with_pattern_large_scale_policy.csv')
  );
  eBoth.enableLog(false);
  eBoth.addNamedMatchingFunc('g', Util.keyMatch4Func);
  eBoth.addNamedDomainMatchingFunc('g', Util.keyMatch4Func);
  suite.add('BenchmarkBuildRoleLinksWithPatternAndDomainPatternLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await eBoth.buildRoleLinks();
      deferred.resolve();
    },
  });

  // BenchmarkHasLinkWithPatternLarge
  const eHasPattern = await newEnforcer(
    resolve('examples/performance/rbac_with_pattern_large_scale_model.conf'),
    resolve('examples/performance/rbac_with_pattern_large_scale_policy.csv')
  );
  eHasPattern.enableLog(false);
  eHasPattern.addNamedMatchingFunc('g', Util.keyMatch4Func);
  await eHasPattern.buildRoleLinks();
  const rmHasPattern = eHasPattern.getRoleManager();
  suite.add('BenchmarkHasLinkWithPatternLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await rmHasPattern.hasLink('staffUser1001', 'staff001', '/orgs/1/sites/site001');
      deferred.resolve();
    },
  });

  // BenchmarkHasLinkWithDomainPatternLarge
  const eHasDomainPattern = await newEnforcer(
    resolve('examples/performance/rbac_with_pattern_large_scale_model.conf'),
    resolve('examples/performance/rbac_with_pattern_large_scale_policy.csv')
  );
  eHasDomainPattern.enableLog(false);
  eHasDomainPattern.addNamedDomainMatchingFunc('g', Util.keyMatch4Func);
  await eHasDomainPattern.buildRoleLinks();
  const rmHasDomainPattern = eHasDomainPattern.getRoleManager();
  suite.add('BenchmarkHasLinkWithDomainPatternLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await rmHasDomainPattern.hasLink('staffUser1001', 'staff001', '/orgs/1/sites/site001');
      deferred.resolve();
    },
  });

  // BenchmarkHasLinkWithPatternAndDomainPatternLarge
  const eHasBoth = await newEnforcer(
    resolve('examples/performance/rbac_with_pattern_large_scale_model.conf'),
    resolve('examples/performance/rbac_with_pattern_large_scale_policy.csv')
  );
  eHasBoth.enableLog(false);
  eHasBoth.addNamedMatchingFunc('g', Util.keyMatch4Func);
  eHasBoth.addNamedDomainMatchingFunc('g', Util.keyMatch4Func);
  await eHasBoth.buildRoleLinks();
  const rmHasBoth = eHasBoth.getRoleManager();
  suite.add('BenchmarkHasLinkWithPatternAndDomainPatternLarge', {
    defer: true,
    fn: async (deferred: any) => {
      await rmHasBoth.hasLink('staffUser1001', 'staff001', '/orgs/1/sites/site001');
      deferred.resolve();
    },
  });
}
