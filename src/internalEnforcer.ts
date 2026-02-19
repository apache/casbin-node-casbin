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

import { CoreEnforcer } from './coreEnforcer';
import { BatchAdapter } from './persist';
import { UpdatableAdapter } from './persist';
import { PolicyOp } from './model';

/**
 * InternalEnforcer = CoreEnforcer + Internal API.
 */
export class InternalEnforcer extends CoreEnforcer {
  /**
   * addPolicyInternal adds a rule to the current policy.
   */
  protected async addPolicyInternal(sec: string, ptype: string, rule: string[], useWatcher: boolean): Promise<boolean> {
    if (this.model.hasPolicy(sec, ptype, rule)) {
      return false;
    }

    // Persist when an adapter is configured and autoSave is enabled.
    if (this.adapter && this.autoSave) {
      try {
        await this.adapter.addPolicy(sec, ptype, rule);
      } catch (e) {
        if (e instanceof Error && e.message !== 'not implemented') {
          throw e;
        }
      }
    }

    if (useWatcher) {
      if (this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForAddPolicy(sec, ptype, ...rule);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const ok = this.model.addPolicy(sec, ptype, rule);

    if (sec === 'g' && ok) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, [rule]);
    }
    return ok;
  }

  // addPolicies adds rules to the current policy.
  // removePolicies removes rules from the current policy.
  protected async addPoliciesInternal(sec: string, ptype: string, rules: string[][], useWatcher: boolean): Promise<boolean> {
    for (const rule of rules) {
      if (this.model.hasPolicy(sec, ptype, rule)) {
        return false;
      }
    }

    // Persist when an adapter is configured and autoSave is enabled.
    if (this.adapter && this.autoSave) {
      if ('addPolicies' in this.adapter) {
        try {
          await this.adapter.addPolicies(sec, ptype, rules);
        } catch (e) {
          if (e instanceof Error && e.message !== 'not implemented') {
            throw e;
          }
        }
      } else {
        throw new Error('cannot to save policy, the adapter does not implement the BatchAdapter');
      }
    }

    if (useWatcher) {
      if (this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForAddPolicies(sec, ptype, ...rules);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const [ok, effects] = await this.model.addPolicies(sec, ptype, rules);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, effects);
    }
    return ok;
  }

  /**
   * addPoliciesInternalEx adds rules to the current policy.
   * Unlike addPoliciesInternal, this method will filter out rules that already exist
   * and continue to add the remaining rules instead of returning false immediately.
   */
  protected async addPoliciesInternalEx(sec: string, ptype: string, rules: string[][], useWatcher: boolean): Promise<boolean> {
    // Filter out existing rules
    const newRules = rules.filter((rule) => !this.model.hasPolicy(sec, ptype, rule));

    // If no new rules to add, return false
    if (newRules.length === 0) {
      return false;
    }

    // Persist when an adapter is configured and autoSave is enabled.
    if (this.adapter && this.autoSave) {
      if ('addPolicies' in this.adapter) {
        try {
          await this.adapter.addPolicies(sec, ptype, newRules);
        } catch (e) {
          if (e instanceof Error && e.message !== 'not implemented') {
            throw e;
          }
        }
      } else {
        throw new Error('cannot save policy, the adapter does not implement the BatchAdapter');
      }
    }

    if (useWatcher) {
      if (this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForAddPolicies(sec, ptype, ...newRules);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const [ok, effects] = await this.model.addPolicies(sec, ptype, newRules);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, effects);
    }
    return ok;
  }

  /**
   * updatePolicyInternal updates a rule from the current policy.
   */
  protected async updatePolicyInternal(
    sec: string,
    ptype: string,
    oldRule: string[],
    newRule: string[],
    useWatcher: boolean
  ): Promise<boolean> {
    if (!this.model.hasPolicy(sec, ptype, oldRule)) {
      return false;
    }
    // Persist when an adapter is configured and autoSave is enabled.
    if (this.adapter && this.autoSave) {
      if ('updatePolicy' in this.adapter) {
        try {
          await this.adapter.updatePolicy(sec, ptype, oldRule, newRule);
        } catch (e) {
          if (e instanceof Error && e.message !== 'not implemented') {
            throw e;
          }
        }
      } else {
        throw new Error('cannot to update policy, the adapter does not implement the UpdatableAdapter');
      }
    }

    if (useWatcher) {
      if (this.autoNotifyWatcher) {
        // In fact I think it should wait for the respond, but they implement add_policy() like this
        // error intentionally ignored
        if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const ok = this.model.updatePolicy(sec, ptype, oldRule, newRule);
    if (sec === 'g' && ok) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, [oldRule]);
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, [newRule]);
    }

    return ok;
  }

  /**
   * removePolicyInternal removes a rule from the current policy.
   */
  protected async removePolicyInternal(sec: string, ptype: string, rule: string[], useWatcher: boolean): Promise<boolean> {
    if (!this.model.hasPolicy(sec, ptype, rule)) {
      return false;
    }

    // Persist when an adapter is configured and autoSave is enabled.
    if (this.adapter && this.autoSave) {
      try {
        await this.adapter.removePolicy(sec, ptype, rule);
      } catch (e) {
        if (e instanceof Error && e.message !== 'not implemented') {
          throw e;
        }
      }
    }

    if (useWatcher) {
      if (this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForRemovePolicy(sec, ptype, ...rule);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const ok = await this.model.removePolicy(sec, ptype, rule);
    if (sec === 'g' && ok) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, [rule]);
    }
    return ok;
  }

  // removePolicies removes rules from the current policy.
  protected async removePoliciesInternal(sec: string, ptype: string, rules: string[][], useWatcher: boolean): Promise<boolean> {
    for (const rule of rules) {
      if (!this.model.hasPolicy(sec, ptype, rule)) {
        return false;
      }
    }

    // Persist when an adapter is configured and autoSave is enabled.
    if (this.adapter && this.autoSave) {
      if ('removePolicies' in this.adapter) {
        try {
          await this.adapter.removePolicies(sec, ptype, rules);
        } catch (e) {
          if (e instanceof Error && e.message !== 'not implemented') {
            throw e;
          }
        }
      } else {
        throw new Error('cannot to save policy, the adapter does not implement the BatchAdapter');
      }
    }

    if (useWatcher) {
      if (this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForRemovePolicies(sec, ptype, ...rules);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const [ok, effects] = this.model.removePolicies(sec, ptype, rules);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, effects);
    }
    return ok;
  }

  /**
   * removeFilteredPolicyInternal removes rules based on field filters from the current policy.
   */
  protected async removeFilteredPolicyInternal(
    sec: string,
    ptype: string,
    fieldIndex: number,
    fieldValues: string[],
    useWatcher: boolean
  ): Promise<boolean> {
    // Persist when an adapter is configured and autoSave is enabled.
    if (this.adapter && this.autoSave) {
      try {
        await this.adapter.removeFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues);
      } catch (e) {
        if (e instanceof Error && e.message !== 'not implemented') {
          throw e;
        }
      }
    }

    if (useWatcher) {
      if (this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForRemoveFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const [ok, effects] = this.model.removeFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, effects);
    }
    return ok;
  }

  /**
   * get field index in model.fieldMap.
   */
  public getFieldIndex(ptype: string, field: string): number {
    return this.model.getFieldIndex(ptype, field);
  }

  /**
   *  set index of field
   */
  public setFieldIndex(ptype: string, field: string, index: number): void {
    const assertion = this.model.model.get('p')?.get(ptype);
    assertion?.fieldIndexMap.set(field, index);
  }

  protected async addPolicyWithoutNotify(sec: string, ptype: string, rule: string[]): Promise<boolean> {
    if (this.model.hasPolicy(sec, ptype, rule)) {
      return false;
    }

    const ok = this.model.addPolicy(sec, ptype, rule);
    if (sec === 'g' && ok) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, [rule]);
    }
    return ok;
  }

  protected async addPoliciesWithoutNotify(sec: string, ptype: string, rules: string[][]): Promise<boolean> {
    for (const rule of rules) {
      if (this.model.hasPolicy(sec, ptype, rule)) {
        return false;
      }
    }

    const [ok, effects] = await this.model.addPolicies(sec, ptype, rules);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, effects);
    }
    return ok;
  }

  protected async addPoliciesWithoutNotifyEx(sec: string, ptype: string, rules: string[][]): Promise<boolean> {
    const newRules = rules.filter((rule) => !this.model.hasPolicy(sec, ptype, rule));
    if (newRules.length === 0) {
      return false;
    }

    const [ok, effects] = await this.model.addPolicies(sec, ptype, newRules);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, effects);
    }
    return ok;
  }

  protected async updatePolicyWithoutNotify(sec: string, ptype: string, oldRule: string[], newRule: string[]): Promise<boolean> {
    if (!this.model.hasPolicy(sec, ptype, oldRule)) {
      return false;
    }

    const ok = this.model.updatePolicy(sec, ptype, oldRule, newRule);
    if (sec === 'g' && ok) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, [oldRule]);
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, [newRule]);
    }
    return ok;
  }

  protected async removePolicyWithoutNotify(sec: string, ptype: string, rule: string[]): Promise<boolean> {
    if (!this.model.hasPolicy(sec, ptype, rule)) {
      return false;
    }

    const ok = await this.model.removePolicy(sec, ptype, rule);
    if (sec === 'g' && ok) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, [rule]);
    }
    return ok;
  }

  protected async removePoliciesWithoutNotify(sec: string, ptype: string, rules: string[][]): Promise<boolean> {
    for (const rule of rules) {
      if (!this.model.hasPolicy(sec, ptype, rule)) {
        return false;
      }
    }

    const [ok, effects] = this.model.removePolicies(sec, ptype, rules);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, effects);
    }
    return ok;
  }

  protected async removeFilteredPolicyWithoutNotify(
    sec: string,
    ptype: string,
    fieldIndex: number,
    fieldValues: string[]
  ): Promise<boolean> {
    const [ok, effects] = this.model.removeFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, effects);
    }
    return ok;
  }

  protected async updatePoliciesWithoutNotify(sec: string, ptype: string, oldRules: string[][], newRules: string[][]): Promise<boolean> {
    // Mirror the Go updatePoliciesWithoutNotify; reuse the existing internal flow.
    // Because updatePoliciesInternal isn't implemented yet, fall back to per-item updates.
    if (oldRules.length !== newRules.length) {
      throw new Error('the length of oldRules should be equal to the length of newRules');
    }
    for (let i = 0; i < oldRules.length; i++) {
      const ok = await this.updatePolicyWithoutNotify(sec, ptype, oldRules[i], newRules[i]);
      if (!ok) {
        return false;
      }
    }
    return true;
  }
}
