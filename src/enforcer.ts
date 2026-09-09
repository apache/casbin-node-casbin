// Copyright 2018 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { ManagementEnforcer } from './managementEnforcer';
import { Model, newModelFromFile } from './model';
import { Adapter, FileAdapter, getDefaultFileSystem, setDefaultFileSystem, StringAdapter } from './persist';
import { getLogger } from './log';
import { arrayRemoveDuplicates } from './util';
import { FieldIndex } from './constants';

/**
 * Enforcer = ManagementEnforcer + RBAC API.
 */
export class Enforcer extends ManagementEnforcer {
  /**
   * initWithFile initializes an enforcer with a model file and a policy file.
   * @param modelPath model file path
   * @param policyPath policy file path
   * @param lazyLoad lazyLoad whether to load policy at initial time
   */
  public async initWithFile(modelPath: string, policyPath: string, lazyLoad = false): Promise<void> {
    const a = new FileAdapter(policyPath, this.fs);
    await this.initWithAdapter(modelPath, a, lazyLoad);
  }

  /**
   * initWithFile initializes an enforcer with a model file and a policy file.
   * @param modelPath model file path
   * @param policyString policy CSV string
   * @param lazyLoad whether to load policy at initial time
   */
  public async initWithString(modelPath: string, policyString: string, lazyLoad = false): Promise<void> {
    const a = new StringAdapter(policyString);
    await this.initWithAdapter(modelPath, a, lazyLoad);
  }

  /**
   * initWithAdapter initializes an enforcer with a database adapter.
   * @param modelPath model file path
   * @param adapter current adapter instance
   * @param lazyLoad whether to load policy at initial time
   */
  public async initWithAdapter(modelPath: string, adapter: Adapter, lazyLoad = false): Promise<void> {
    const m = newModelFromFile(modelPath, this.fs);
    await this.initWithModelAndAdapter(m, adapter, lazyLoad);

    this.modelPath = modelPath;
  }

  /**
   * initWithModelAndAdapter initializes an enforcer with a model and a database adapter.
   * @param m model instance
   * @param adapter current adapter instance
   * @param lazyLoad whether to load policy at initial time
   */
  public async initWithModelAndAdapter(m: Model, adapter?: Adapter, lazyLoad = false): Promise<void> {
    if (adapter) {
      this.adapter = adapter;
    }

    this.model = m;
    this.model.printModel();

    this.initRmMap();

    if (!lazyLoad && this.adapter) {
      await this.loadPolicy();
    }
  }

  /**
   * getRolesForUser gets the roles that a user has.
   *
   * @param name the user.
   * @param domain the domain.
   * @return the roles that the user has.
   */
  public async getRolesForUser(name: string, domain?: string): Promise<string[]> {
    const rm = this.rmMap.get('g');
    if (rm) {
      if (domain === undefined) {
        return rm.getRoles(name);
      } else {
        return rm.getRoles(name, domain);
      }
    }
    throw new Error("RoleManager didn't exist.");
  }

  /**
   * getUsersForRole gets the users that has a role.
   *
   * @param name the role.
   * @param domain the domain.
   * @return the users that has the role.
   */
  public async getUsersForRole(name: string, domain?: string): Promise<string[]> {
    const rm = this.rmMap.get('g');
    if (rm) {
      if (domain === undefined) {
        return rm.getUsers(name);
      } else {
        return rm.getUsers(name, domain);
      }
    }
    throw new Error("RoleManager didn't exist.");
  }

  /**
   * hasRoleForUser determines whether a user has a role.
   *
   * @param name the user.
   * @param role the role.
   * @param domain the domain.
   * @return whether the user has the role.
   */
  public async hasRoleForUser(name: string, role: string, domain?: string): Promise<boolean> {
    const roles = await this.getRolesForUser(name, domain);
    let hasRole = false;
    for (const r of roles) {
      if (r === role) {
        hasRole = true;
        break;
      }
    }

    return hasRole;
  }

  /**
   * addRoleForUser adds a role for a user.
   * Returns false if the user already has the role (aka not affected).
   *
   * @param user the user.
   * @param role the role.
   * @param domain the domain.
   * @return succeeds or not.
   */
  public async addRoleForUser(user: string, role: string, domain?: string): Promise<boolean> {
    if (domain === undefined) {
      return this.addGroupingPolicy(user, role);
    } else {
      return this.addGroupingPolicy(user, role, domain);
    }
  }

  /**
   * deleteRoleForUser deletes a role for a user.
   * Returns false if the user does not have the role (aka not affected).
   *
   * @param user the user.
   * @param role the role.
   * @param domain the domain.
   * @return succeeds or not.
   */
  public async deleteRoleForUser(user: string, role: string, domain?: string): Promise<boolean> {
    if (!user) {
      throw new Error('user must not be empty');
    }
    if (!role) {
      throw new Error('role must not be empty');
    }
    if (domain === undefined) {
      return this.removeGroupingPolicy(user, role);
    } else {
      return this.removeGroupingPolicy(user, role, domain);
    }
  }

  /**
   * deleteRolesForUser deletes all roles for a user.
   * Returns false if the user does not have any roles (aka not affected).
   *
   * @param user the user.
   * @param domain the domain.
   * @return succeeds or not.
   */
  public async deleteRolesForUser(user: string, domain?: string): Promise<boolean> {
    if (!user) {
      throw new Error('user must not be empty');
    }
    if (domain === undefined) {
      const subIndex = this.getFieldIndex('p', FieldIndex.Subject);
      return this.removeFilteredGroupingPolicy(subIndex, user);
    } else {
      return this.removeFilteredGroupingPolicy(0, user, '', domain);
    }
  }

  /**
   * deleteUser deletes a user.
   * Returns false if the user does not exist (aka not affected).
   *
   * @param user the user.
   * @return succeeds or not.
   */
  public async deleteUser(user: string): Promise<boolean> {
    if (!user) {
      throw new Error('user must not be empty');
    }
    const subIndex = this.getFieldIndex('p', FieldIndex.Subject);
    const res1 = await this.removeFilteredGroupingPolicy(subIndex, user);
    const res2 = await this.removeFilteredPolicy(subIndex, user);
    return res1 || res2;
  }

  /**
   * deleteRole deletes a role.
   * Returns false if the role does not exist (aka not affected).
   *
   * @param role the role.
   * @return succeeds or not.
   */
  public async deleteRole(role: string): Promise<boolean> {
    if (!role) {
      throw new Error('role must not be empty');
    }
    const subIndex = this.getFieldIndex('p', FieldIndex.Subject);
    const res1 = await this.removeFilteredGroupingPolicy(subIndex, role);
    const res2 = await this.removeFilteredPolicy(subIndex, role);
    return res1 || res2;
  }

  /**
   * deletePermission deletes a permission.
   * Returns false if the permission does not exist (aka not affected).
   *
   * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
   * @return succeeds or not.
   */
  public async deletePermission(...permission: string[]): Promise<boolean> {
    if (permission.length === 0) {
      throw new Error('permission must not be empty');
    }
    return this.removeFilteredPolicy(1, ...permission);
  }

  /**
   * addPermissionForUser adds a permission for a user or role.
   * Returns false if the user or role already has the permission (aka not affected).
   *
   * @param user the user.
   * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
   * @return succeeds or not.
   */
  public async addPermissionForUser(user: string, ...permission: string[]): Promise<boolean> {
    permission.unshift(user);
    return this.addPolicy(...permission);
  }

  /**
   * deletePermissionForUser deletes a permission for a user or role.
   * Returns false if the user or role does not have the permission (aka not affected).
   *
   * @param user the user.
   * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
   * @return succeeds or not.
   */
  public async deletePermissionForUser(user: string, ...permission: string[]): Promise<boolean> {
    if (!user) {
      throw new Error('user must not be empty');
    }
    permission.unshift(user);
    return this.removePolicy(...permission);
  }

  /**
   * deletePermissionsForUser deletes permissions for a user or role.
   * Returns false if the user or role does not have any permissions (aka not affected).
   *
   * @param user the user.
   * @return succeeds or not.
   */
  public async deletePermissionsForUser(user: string): Promise<boolean> {
    if (!user) {
      throw new Error('user must not be empty');
    }
    const subIndex = this.getFieldIndex('p', FieldIndex.Subject);
    return this.removeFilteredPolicy(subIndex, user);
  }

  /**
   * getPermissionsForUser gets permissions for a user or role.
   *
   * @param user the user.
   * @param domain the domain, optional. When given, only the permissions of that domain are returned.
   * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
   */
  public async getPermissionsForUser(user: string, ...domain: string[]): Promise<string[][]> {
    return this.getNamedPermissionsForUser('p', user, ...domain);
  }

  /**
   * getNamedPermissionsForUser gets permissions for a user or role by the named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param user the user.
   * @param domain the domain, optional. When given, only the permissions of that domain are returned.
   * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
   */
  public async getNamedPermissionsForUser(ptype: string, user: string, ...domain: string[]): Promise<string[][]> {
    const subIndex = this.getFieldIndex(ptype, FieldIndex.Subject);
    if (subIndex === -1) {
      return [];
    }
    if (domain.length === 0) {
      return this.getFilteredNamedPolicy(ptype, subIndex, user);
    }

    // The domain is not necessarily the token right after the subject, so it has to be
    // looked up in the model instead of being assumed to sit at a fixed index.
    const domIndex = this.getFieldIndex(ptype, FieldIndex.Domain);
    if (domIndex === -1) {
      return this.getFilteredNamedPolicy(ptype, subIndex, user);
    }

    const start = Math.min(subIndex, domIndex);
    // "" means not to match that field.
    const fieldValues = new Array<string>(Math.abs(subIndex - domIndex) + 1).fill('');
    fieldValues[subIndex - start] = user;
    fieldValues[domIndex - start] = domain[0];
    return this.getFilteredNamedPolicy(ptype, start, ...fieldValues);
  }

  /**
   * hasPermissionForUser determines whether a user has a permission.
   *
   * @param user the user.
   * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
   * @return whether the user has the permission.
   */
  public async hasPermissionForUser(user: string, ...permission: string[]): Promise<boolean> {
    permission.unshift(user);
    return this.hasPolicy(...permission);
  }

  /**
   * getImplicitRolesForUser gets implicit roles that a user has.
   * Compared to getRolesForUser(), this function retrieves indirect roles besides direct roles.
   * For example:
   * g, alice, role:admin
   * g, role:admin, role:user
   *
   * getRolesForUser("alice") can only get: ["role:admin"].
   * But getImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
   */
  public async getImplicitRolesForUser(name: string, ...domain: string[]): Promise<string[]> {
    const res: string[] = [];

    // Each role definition is a hierarchy of its own, so every role manager is walked
    // separately and the results are concatenated. Following a "g" link and then a "g2"
    // link off the role it led to would mix two unrelated hierarchies.
    for (const ptype of this.rmMap.keys()) {
      res.push(...(await this.getNamedImplicitRolesForUser(ptype, name, ...domain)));
    }

    return res;
  }

  /**
   * getNamedImplicitRolesForUser gets implicit roles that a user has, using only the
   * given role definition. Compared to getImplicitRolesForUser(), which walks every
   * role manager, this one is restricted to "g", "g2", ...
   *
   * @param ptype the role definition type, can be "g", "g2", "g3", ..
   * @param name the user.
   * @param domain the domain, optional.
   */
  public async getNamedImplicitRolesForUser(ptype: string, name: string, ...domain: string[]): Promise<string[]> {
    const rm = this.rmMap.get(ptype);
    if (!rm) {
      throw new Error(`role manager ${ptype} is not initialized`);
    }

    if (rm.getImplicitRoles) {
      return rm.getImplicitRoles(name, ...domain);
    }

    // Fallback for role managers that only expose one hop. It cannot honour a hierarchy
    // level limit, since that limit belongs to the role manager.
    const res: string[] = [];
    const visited = new Set<string>([name]);
    const q = [name];
    let n: string | undefined;
    while ((n = q.shift()) !== undefined) {
      const roles = await rm.getRoles(n, ...domain);
      roles.forEach((r) => {
        if (!visited.has(r)) {
          visited.add(r);
          res.push(r);
          q.push(r);
        }
      });
    }

    return res;
  }

  /**
   * getImplicitPermissionsForUser gets implicit permissions for a user or role.
   * Compared to getPermissionsForUser(), this function retrieves permissions for inherited roles.
   * For example:
   * p, admin, data1, read
   * p, alice, data2, read
   * g, alice, admin
   *
   * getPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
   * But getImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
   */
  public async getImplicitPermissionsForUser(user: string, ...domain: string[]): Promise<string[][]> {
    return this.getNamedImplicitPermissionsForUser('p', 'g', user, ...domain);
  }

  /**
   * getNamedImplicitPermissionsForUser gets implicit permissions for a user or role
   * by the named policy and the named role definition.
   *
   * When a domain is given, a policy rule is kept if its domain field matches that
   * domain according to the role manager, so a rule written for a wildcard domain
   * (e.g. "p, admin, data, read, *") is reported for every concrete domain once a
   * domain matching function has been registered with addNamedDomainMatchingFunc().
   * The returned rule then carries the requested domain instead of the pattern.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param gtype the role definition type, can be "g", "g2", "g3", ..
   * @param user the user.
   * @param domain the domain, optional.
   */
  public async getNamedImplicitPermissionsForUser(ptype: string, gtype: string, user: string, ...domain: string[]): Promise<string[][]> {
    if (domain.length > 1) {
      throw new Error('error: domain should be 1 parameter');
    }

    const rm = this.rmMap.get(gtype);
    if (!rm) {
      throw new Error(`role manager ${gtype} is not initialized`);
    }

    const roles = await this.getNamedImplicitRolesForUser(gtype, user, ...domain);
    const policyRoles = new Set<string>(roles);
    policyRoles.add(user);

    // The subject and the domain are not necessarily the first two tokens, so both
    // have to be looked up in the model instead of being assumed to sit at a fixed index.
    const subIndex = this.getFieldIndex(ptype, FieldIndex.Subject);
    if (subIndex === -1) {
      throw new Error(`${FieldIndex.Subject} index is not set, please use enforcer.setFieldIndex() to set index`);
    }

    const permission: string[][] = [];
    const policy = await this.getNamedPolicy(ptype);

    if (domain.length === 0) {
      for (const rule of policy) {
        if (policyRoles.has(rule[subIndex])) {
          permission.push([...rule]);
        }
      }
      return permission;
    }

    const domIndex = this.getFieldIndex(ptype, FieldIndex.Domain);
    if (domIndex === -1) {
      throw new Error(`${FieldIndex.Domain} index is not set, please use enforcer.setFieldIndex() to set index`);
    }

    const d = domain[0];
    for (const rule of policy) {
      // match() falls back to an exact comparison unless a domain matching function
      // has been registered, so a "*" rule only spreads across domains on request.
      const matched = rm.match ? rm.match(d, rule[domIndex]) : d === rule[domIndex];
      if (!matched) {
        continue;
      }
      if (policyRoles.has(rule[subIndex])) {
        const newRule = [...rule];
        newRule[domIndex] = d;
        permission.push(newRule);
      }
    }

    return permission;
  }

  /**
   * getImplicitResourcesForUser returns all policies that user obtaining in domain.
   */
  public async getImplicitResourcesForUser(user: string, ...domain: string[]): Promise<string[][]> {
    const permissions = await this.getImplicitPermissionsForUser(user, ...domain);
    const res: string[][] = [];
    for (const permission of permissions) {
      if (permission[0] === user) {
        res.push(permission);
        continue;
      }
      let resLocal: string[][] = [[user]];
      const tokensLength: number = permission.length;
      const t: string[][] = [];
      for (const token of permission) {
        if (token === permission[0]) {
          continue;
        }
        const tokens: string[] = await this.getImplicitUsersForRole(token, ...domain);
        tokens.push(token);
        t.push(tokens);
      }
      for (let i = 0; i < tokensLength - 1; i++) {
        const n: string[][] = [];
        for (const tokens of t[i]) {
          for (const policy of resLocal) {
            const t: string[] = [...policy];
            t.push(tokens);
            n.push(t);
          }
        }
        resLocal = n;
      }
      res.push(...resLocal);
    }
    return res;
  }

  /**
   * getImplicitUsersForRole gets implicit users that a role has.
   * Compared to getUsersForRole(), this function retrieves indirect users besides direct users.
   * For example:
   * g, alice, role:admin
   * g, role:admin, role:user
   *
   * getUsersForRole("user") can only get: ["role:admin"].
   * But getImplicitUsersForRole("user") will get: ["role:admin", "alice"].
   */
  public async getImplicitUsersForRole(role: string, ...domain: string[]): Promise<string[]> {
    const res = new Set<string>();
    const q = [role];
    let n: string | undefined;
    while ((n = q.shift()) !== undefined) {
      for (const rm of this.rmMap.values()) {
        const user = await rm.getUsers(n, ...domain);
        user.forEach((u) => {
          if (!res.has(u)) {
            res.add(u);
            q.push(u);
          }
        });
      }
    }

    return Array.from(res);
  }

  /**
   * getRolesForUserInDomain gets the roles that a user has inside a domain
   * An alias for getRolesForUser with the domain params.
   *
   * @param name the user.
   * @param domain the domain.
   * @return the roles that the user has.
   */
  public async getRolesForUserInDomain(name: string, domain: string): Promise<string[]> {
    return this.getRolesForUser(name, domain);
  }

  /**
   * getUsersForRoleInFomain gets the users that has a role inside a domain
   * An alias for getUsesForRole with the domain params.
   *
   * @param name the role.
   * @param domain the domain.
   * @return the users that has the role.
   */
  public async getUsersForRoleInDomain(name: string, domain: string): Promise<string[]> {
    return this.getUsersForRole(name, domain);
  }

  /**
   * getImplicitUsersForPermission gets implicit users for a permission.
   * For example:
   * p, admin, data1, read
   * p, bob, data1, read
   * g, alice, admin
   *
   * getImplicitUsersForPermission("data1", "read") will get: ["alice", "bob"].
   * Note: only users will be returned, roles (2nd arg in "g") will be excluded.
   */
  public async getImplicitUsersForPermission(...permission: string[]): Promise<string[]> {
    const res: string[] = [];
    const policySubjects = await this.getAllSubjects();
    const subjects = arrayRemoveDuplicates([...policySubjects, ...this.model.getValuesForFieldInPolicyAllTypes('g', 0)]);
    const inherits = this.model.getValuesForFieldInPolicyAllTypes('g', 1);

    for (const user of subjects) {
      const allowed = await this.enforce(user, ...permission);
      if (allowed) {
        res.push(user);
      }
    }

    return res.filter((n) => !inherits.some((m) => n === m));
  }

  /**
   * getDomainsForUser gets all domains that a user has.
   */
  public async getDomainsForUser(user: string): Promise<string[]> {
    const domains: string[] = [];
    for (const rm of this.rmMap.values()) {
      const domain = await rm.getDomains(user);
      domains.push(...domain);
    }
    return domains;
  }

  /**
   * getAllDomains gets all domains.
   */
  public async getAllDomains(): Promise<string[]> {
    const domains: string[] = [];
    for (const rm of this.rmMap.values()) {
      const domain = await rm.getAllDomains();
      domains.push(...domain);
    }
    return arrayRemoveDuplicates(domains);
  }
}

/**
 * NewEnforcerParams is the list of argument combinations accepted by the enforcer factories
 * (newEnforcer, newEnforcerWithClass, newCachedEnforcer and newSyncedEnforcer).
 *
 * The model always comes first, either as a path to a `.conf` file or as an already built Model.
 * It can be followed by a policy source: a path to a `.csv` file (model file only) or an Adapter.
 * A trailing boolean enables the logger, and additionally acts as the `lazyLoad` flag when a model
 * file path is combined with an adapter.
 */
export type NewEnforcerParams =
  | []
  | [enableLog: boolean]
  | [modelPath: string]
  | [modelPath: string, enableLog: boolean]
  | [modelPath: string, policyPath: string]
  | [modelPath: string, policyPath: string, enableLog: boolean]
  | [modelPath: string, adapter: Adapter]
  | [modelPath: string, adapter: Adapter, lazyLoadAndEnableLog: boolean]
  | [model: Model]
  | [model: Model, enableLog: boolean]
  | [model: Model, adapter: Adapter]
  | [model: Model, adapter: Adapter, enableLog: boolean];

export async function newEnforcerWithClass<T extends Enforcer>(enforcer: new () => T, ...params: NewEnforcerParams): Promise<T> {
  // inject the FS
  if (!getDefaultFileSystem()) {
    try {
      if (typeof process !== 'undefined' && process?.versions?.node) {
        const fs = await import('fs');
        const defaultFileSystem = {
          readFileSync(path: string, encoding?: string) {
            return fs.readFileSync(path, { encoding });
          },
          writeFileSync(path: string, text: string, encoding?: string) {
            return fs.writeFileSync(path, text, encoding);
          },
        };
        setDefaultFileSystem(defaultFileSystem);
      }
    } catch (ignored) {}
  }

  const e = new enforcer();

  // NewEnforcerParams already constrains the shape, index it loosely while dispatching
  const args: any[] = params;

  let parsedParamLen = 0;
  if (args.length >= 1) {
    const enableLog = args[args.length - 1];
    if (typeof enableLog === 'boolean') {
      getLogger().enableLog(enableLog);
      parsedParamLen++;
    }
  }

  if (args.length - parsedParamLen === 2) {
    if (typeof args[0] === 'string') {
      if (typeof args[1] === 'string') {
        await e.initWithFile(args[0].toString(), args[1].toString());
      } else {
        await e.initWithAdapter(args[0].toString(), args[1], args[2] === true);
      }
    } else {
      if (typeof args[1] === 'string') {
        throw new Error('Invalid parameters for enforcer.');
      } else {
        await e.initWithModelAndAdapter(args[0], args[1]);
      }
    }
  } else if (args.length - parsedParamLen === 1) {
    if (typeof args[0] === 'string') {
      await e.initWithFile(args[0], '');
    } else {
      await e.initWithModelAndAdapter(args[0]);
    }
  } else if (args.length === parsedParamLen) {
    await e.initWithFile('', '');
  } else {
    throw new Error('Invalid parameters for enforcer.');
  }

  return e;
}

/**
 * newEnforcer creates an enforcer via file or DB.
 *
 * File:
 * ```js
 * const e = new Enforcer('path/to/basic_model.conf', 'path/to/basic_policy.csv');
 * ```
 *
 * MySQL DB:
 * ```js
 * const a = new MySQLAdapter('mysql', 'mysql_username:mysql_password@tcp(127.0.0.1:3306)/');
 * const e = new Enforcer('path/to/basic_model.conf', a);
 * ```
 *
 * @param params
 */
export async function newEnforcer(...params: NewEnforcerParams): Promise<Enforcer> {
  return newEnforcerWithClass(Enforcer, ...params);
}
