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

import { RoleManager } from './roleManager';
import { getLogger, logPrint } from '../log';

export type MatchingFunc = (arg1: string, arg2: string) => boolean;

// DEFAULT_DOMAIN defines the default domain space.
const DEFAULT_DOMAIN = 'casbin::default';

// loadOrDefault returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
function loadOrDefault<K, V>(map: Map<K, V>, key: K, value: V): V {
  const read = map.get(key);
  if (read === undefined) {
    map.set(key, value);
    return value;
  }
  return read;
}

/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
  public name: string;
  private roles: Role[];

  constructor(name: string) {
    this.name = name;
    this.roles = [];
  }

  public addRole(role: Role): void {
    if (this.roles.some((n) => n.name === role.name)) {
      return;
    }
    this.roles.push(role);
  }

  public deleteRole(role: Role): void {
    this.roles = this.roles.filter((n) => n.name !== role.name);
  }

  public hasRole(name: string, hierarchyLevel: number): boolean {
    if (this.name === name) {
      return true;
    }
    if (hierarchyLevel <= 0) {
      return false;
    }
    for (const role of this.roles) {
      if (role.hasRole(name, hierarchyLevel - 1)) {
        return true;
      }
    }

    return false;
  }

  public hasDirectRole(name: string): boolean {
    return this.roles.some((n) => n.name === name);
  }

  public toString(): string {
    return this.name + this.roles.join(', ');
  }

  public getRoles(): string[] {
    return this.roles.map((n) => n.name);
  }
}

class Roles extends Map<string, Role> {
  constructor() {
    super();
  }

  public hasRole(name: string, matchingFunc?: MatchingFunc): boolean {
    let ok = false;
    if (matchingFunc) {
      this.forEach((value, key) => {
        if (matchingFunc(name, key)) {
          ok = true;
        }
      });
    } else {
      return this.has(name);
    }
    return ok;
  }

  public createRole(name: string, matchingFunc?: MatchingFunc): Role {
    const role = loadOrDefault(this, name, new Role(name));
    if (matchingFunc) {
      this.forEach((value, key) => {
        if (matchingFunc(name, key) && name !== key) {
          // Add new role to matching role
          const role1 = loadOrDefault(this, key, new Role(key));
          role.addRole(role1);
        }
      });
    }
    return role;
  }
}

// RoleManager provides a default implementation for the RoleManager interface
export class DefaultRoleManager implements RoleManager {
  private allDomains: Map<string, Roles>;
  private maxHierarchyLevel: number;
  private hasPattern = false;
  private hasDomainPattern = false;
  private hasDomainHierarchy = false;
  private domainHierarchyManager: RoleManager;
  private matchingFunc: MatchingFunc;
  private domainMatchingFunc: MatchingFunc;

  /**
   * DefaultRoleManager is the constructor for creating an instance of the
   * default RoleManager implementation.
   *
   * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
   */
  constructor(maxHierarchyLevel: number) {
    this.allDomains = new Map<string, Roles>();
    this.allDomains.set(DEFAULT_DOMAIN, new Roles());
    this.maxHierarchyLevel = maxHierarchyLevel;
  }

  /**
   * addMatchingFunc support use pattern in g
   * @param name name
   * @param fn matching function
   * @deprecated
   */
  public async addMatchingFunc(name: string, fn: MatchingFunc): Promise<void>;

  /**
   * addMatchingFunc support use pattern in g
   * @param fn matching function
   */
  public async addMatchingFunc(fn: MatchingFunc): Promise<void>;

  /**
   * addMatchingFunc support use pattern in g
   * @param name name
   * @param fn matching function
   * @deprecated
   */
  public async addMatchingFunc(name: string | MatchingFunc, fn?: MatchingFunc): Promise<void> {
    this.hasPattern = true;
    if (typeof name === 'string' && fn) {
      this.matchingFunc = fn;
    } else if (typeof name === 'function') {
      this.matchingFunc = name;
    } else {
      throw new Error('error: domain should be 1 parameter');
    }
  }

  /**
   * addDomainMatchingFunc support use domain pattern in g
   * @param fn domain matching function
   * ```
   */
  public async addDomainMatchingFunc(fn: MatchingFunc): Promise<void> {
    this.hasDomainPattern = true;
    this.domainMatchingFunc = fn;
  }

  /**
   * match determines whether the domain str is covered by the domain pattern used
   * in a policy or grouping rule. Without a domain matching function registered,
   * only an exact match counts, which keeps the default behaviour unchanged.
   *
   * @param str the concrete domain, e.g. "tenant1"
   * @param pattern the domain written in the rule, e.g. "*"
   */
  public match(str: string, pattern: string): boolean {
    if (str === pattern) {
      return true;
    }
    if (this.hasDomainPattern) {
      return this.domainMatchingFunc(str, pattern);
    }
    return false;
  }

  /**
   * addDomainHierarchy sets a rolemanager to define role inheritance between domains
   * @param rm RoleManager to define domain hierarchy
   */
  public async addDomainHierarchy(rm: RoleManager): Promise<void> {
    if (!rm?.syncedHasLink) throw Error('Domain hierarchy must be syncronous.');
    this.hasDomainHierarchy = true;
    this.domainHierarchyManager = rm;
  }

  private generateTempRoles(domain: string): Roles {
    if (!this.hasPattern && !this.hasDomainPattern && !this.hasDomainHierarchy) {
      return loadOrDefault(this.allDomains, domain, new Roles());
    }

    const extraDomain = new Set([domain]);
    if (this.hasDomainPattern || this.hasDomainHierarchy) {
      this.allDomains.forEach((value, key) => {
        if (
          (this.hasDomainPattern && this.domainMatchingFunc(domain, key)) ||
          (this.domainHierarchyManager?.syncedHasLink && this.domainHierarchyManager.syncedHasLink(key, domain))
        ) {
          extraDomain.add(key);
        }
      });
    }

    const allRoles = new Roles();
    extraDomain.forEach((dom) => {
      loadOrDefault(this.allDomains, dom, new Roles()).forEach((value, key) => {
        const role1 = allRoles.createRole(value.name, this.matchingFunc);
        value.getRoles().forEach((n) => {
          role1.addRole(allRoles.createRole(n, this.matchingFunc));
        });
      });
    });
    return allRoles;
  }

  /**
   * addLink adds the inheritance link between role: name1 and role: name2.
   * aka role: name1 inherits role: name2.
   * domain is a prefix to the roles.
   */
  public async addLink(name1: string, name2: string, ...domain: string[]): Promise<void> {
    if (domain.length === 0) {
      domain = [DEFAULT_DOMAIN];
    } else if (domain.length > 1) {
      throw new Error('error: domain should be 1 parameter');
    }

    const allRoles = loadOrDefault(this.allDomains, domain[0], new Roles());

    const role1 = loadOrDefault(allRoles, name1, new Role(name1));
    const role2 = loadOrDefault(allRoles, name2, new Role(name2));
    role1.addRole(role2);
  }

  /**
   * clear clears all stored data and resets the role manager to the initial state.
   */
  public async clear(): Promise<void> {
    this.allDomains = new Map();
    this.allDomains.set(DEFAULT_DOMAIN, new Roles());
  }

  /**
   * deleteLink deletes the inheritance link between role: name1 and role: name2.
   * aka role: name1 does not inherit role: name2 any more.
   * domain is a prefix to the roles.
   */
  public async deleteLink(name1: string, name2: string, ...domain: string[]): Promise<void> {
    if (domain.length === 0) {
      domain = [DEFAULT_DOMAIN];
    } else if (domain.length > 1) {
      throw new Error('error: domain should be 1 parameter');
    }

    const allRoles = loadOrDefault(this.allDomains, domain[0], new Roles());

    if (!allRoles.has(name1) || !allRoles.has(name2)) {
      return;
    }

    const role1 = loadOrDefault(allRoles, name1, new Role(name1));
    const role2 = loadOrDefault(allRoles, name2, new Role(name2));
    role1.deleteRole(role2);
  }

  /**
   * hasLink determines whether role: name1 inherits role: name2.
   * domain is a prefix to the roles.
   */
  public syncedHasLink(name1: string, name2: string, ...domain: string[]): boolean {
    if (domain.length === 0) {
      domain = [DEFAULT_DOMAIN];
    } else if (domain.length > 1) {
      throw new Error('error: domain should be 1 parameter');
    }

    if (name1 === name2) {
      return true;
    }

    const allRoles = this.generateTempRoles(domain[0]);

    if (!allRoles.hasRole(name1, this.matchingFunc) || !allRoles.hasRole(name2, this.matchingFunc)) {
      return false;
    }

    const role1 = allRoles.createRole(name1, this.matchingFunc);
    return role1.hasRole(name2, this.maxHierarchyLevel);
  }

  public async hasLink(name1: string, name2: string, ...domain: string[]): Promise<boolean> {
    return new Promise((resolve) => resolve(this.syncedHasLink(name1, name2, ...domain)));
  }

  /**
   * getRoles gets the roles that a subject inherits.
   * domain is a prefix to the roles.
   */
  public async getRoles(name: string, ...domain: string[]): Promise<string[]> {
    if (domain.length === 0) {
      domain = [DEFAULT_DOMAIN];
    } else if (domain.length > 1) {
      throw new Error('error: domain should be 1 parameter');
    }

    const allRoles = this.generateTempRoles(domain[0]);

    if (!allRoles.hasRole(name, this.matchingFunc)) {
      return [];
    }

    return allRoles.createRole(name, this.matchingFunc).getRoles();
  }

  /**
   * getImplicitRoles gets the roles that a subject inherits, directly or through other
   * roles. Compared to getRoles(), which only walks one hop, this follows the whole
   * hierarchy, up to maxHierarchyLevel hops.
   * domain is a prefix to the roles.
   */
  public async getImplicitRoles(name: string, ...domain: string[]): Promise<string[]> {
    if (domain.length === 0) {
      domain = [DEFAULT_DOMAIN];
    } else if (domain.length > 1) {
      throw new Error('error: domain should be 1 parameter');
    }

    // The role graph only has to be resolved once for the whole traversal.
    const allRoles = this.generateTempRoles(domain[0]);

    const res: string[] = [];
    // Seeded with the subject so that a cycle back to it does not report the subject as
    // one of its own roles, and so that the traversal terminates.
    const roleSet = new Set<string>([name]);
    let current = [name];

    for (let level = 0; level < this.maxHierarchyLevel && current.length > 0; level++) {
      const next: string[] = [];
      for (const n of current) {
        if (!allRoles.hasRole(n, this.matchingFunc)) {
          continue;
        }
        allRoles
          .createRole(n, this.matchingFunc)
          .getRoles()
          .forEach((r) => {
            if (!roleSet.has(r)) {
              roleSet.add(r);
              res.push(r);
              next.push(r);
            }
          });
      }
      current = next;
    }

    return res;
  }

  /**
   * getUsers gets the users that inherits a subject.
   * domain is an unreferenced parameter here, may be used in other implementations.
   */
  public async getUsers(name: string, ...domain: string[]): Promise<string[]> {
    if (domain.length === 0) {
      domain = [DEFAULT_DOMAIN];
    } else if (domain.length > 1) {
      throw new Error('error: domain should be 1 parameter');
    }

    const allRoles = this.generateTempRoles(domain[0]);

    if (!allRoles.hasRole(name, this.matchingFunc)) {
      return [];
    }
    const users = [];
    for (const user of allRoles.values()) {
      if (user.hasDirectRole(name)) users.push(user.name);
    }
    return users;
  }

  /**
   * printRoles prints all the roles to log.
   */
  public async printRoles(): Promise<void> {
    if (getLogger().isEnable()) {
      [...this.allDomains.values()].forEach((n) => {
        logPrint(n.toString());
      });
    }
  }

  /**
   * getDomains gets domains that a user has.
   */
  public async getDomains(name: string): Promise<string[]> {
    const domains: string[] = [];
    this.allDomains.forEach((roles, domain) => {
      // Skip the default domain if there are other domains
      if (domain === DEFAULT_DOMAIN && this.allDomains.size > 1) {
        return;
      }
      const role = roles.get(name);
      if (role) {
        // Check if role has any roles it inherits OR if any other role inherits from it
        const hasRoles = role.getRoles().length > 0;
        const hasUsers = this.hasUserForRole(roles, name);
        if (hasRoles || hasUsers) {
          domains.push(domain);
        }
      }
    });
    return domains;
  }

  /**
   * getAllDomains gets all domains.
   */
  public async getAllDomains(): Promise<string[]> {
    const domains = Array.from(this.allDomains.keys());
    // Filter out the default domain if there are other domains
    if (domains.length > 1) {
      return domains.filter((d) => d !== DEFAULT_DOMAIN);
    }
    return domains;
  }

  private hasUserForRole(roles: Roles, name: string): boolean {
    for (const role of roles.values()) {
      if (role.hasDirectRole(name)) {
        return true;
      }
    }
    return false;
  }
}
