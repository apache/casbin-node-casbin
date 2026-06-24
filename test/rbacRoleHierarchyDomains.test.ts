import { newEnforcer } from '../src';

describe('Test Role Hierarchy with Domains and Wildcards', () => {
  test('getImplicitPermissionsForUser should handle wildcard domains', async () => {
    const e = await newEnforcer(
      'examples/rbac_with_role_hierarchy_domains_model.conf',
      'examples/rbac_with_role_hierarchy_domains_policy.csv'
    );

    // Test michael in tenant1 - should get permissions from abstract_role1 with domain *
    const michaelPerms = await e.getImplicitPermissionsForUser('michael', 'tenant1');

    // Michael should have:
    // - abstract_role1 permissions (devis read/create) with domain *
    expect(michaelPerms).toContainEqual(['abstract_role1', '*', 'devis', 'read']);
    expect(michaelPerms).toContainEqual(['abstract_role1', '*', 'devis', 'create']);

    // Test thomas in tenant1 - should get permissions from abstract_role2 with domain *
    const thomasPerms = await e.getImplicitPermissionsForUser('thomas', 'tenant1');

    // Thomas should have:
    // - abstract_role2 permissions (devis read, organization read/write) with domain *
    expect(thomasPerms).toContainEqual(['abstract_role2', '*', 'devis', 'read']);
    expect(thomasPerms).toContainEqual(['abstract_role2', '*', 'organization', 'read']);
    expect(thomasPerms).toContainEqual(['abstract_role2', '*', 'organization', 'write']);

    // Test theo with super_user - should get permissions from abstract_role2 with domain *
    const theoPerms = await e.getImplicitPermissionsForUser('theo', 'tenant1');

    // Theo should have:
    // - abstract_role2 permissions (devis read, organization read/write) with domain *
    expect(theoPerms).toContainEqual(['abstract_role2', '*', 'devis', 'read']);
    expect(theoPerms).toContainEqual(['abstract_role2', '*', 'organization', 'read']);
    expect(theoPerms).toContainEqual(['abstract_role2', '*', 'organization', 'write']);
  });

  test('enforce should work with wildcard domains in role hierarchy', async () => {
    const e = await newEnforcer(
      'examples/rbac_with_role_hierarchy_domains_model.conf',
      'examples/rbac_with_role_hierarchy_domains_policy.csv'
    );

    // Michael in tenant1 should be able to read devis
    expect(await e.enforce('michael', 'tenant1', 'devis', 'read')).toBe(true);
    expect(await e.enforce('michael', 'tenant1', 'devis', 'create')).toBe(true);

    // Michael in tenant2 should NOT have access (not assigned to tenant2)
    expect(await e.enforce('michael', 'tenant2', 'devis', 'read')).toBe(false);

    // Antoine in tenant2 should be able to read devis
    expect(await e.enforce('antoine', 'tenant2', 'devis', 'read')).toBe(true);

    // Thomas in tenant1 should have organization permissions
    expect(await e.enforce('thomas', 'tenant1', 'organization', 'read')).toBe(true);
    expect(await e.enforce('thomas', 'tenant1', 'organization', 'write')).toBe(true);

    // Theo with super_user should have access to any tenant
    expect(await e.enforce('theo', 'tenant1', 'organization', 'read')).toBe(true);
    expect(await e.enforce('theo', 'tenant2', 'organization', 'read')).toBe(true);
    expect(await e.enforce('theo', 'tenant3', 'organization', 'read')).toBe(true);
  });
});
