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

import { InternalEnforcer } from './internalEnforcer';
import { MatchingFunction } from './model';

/**
 * ManagementEnforcer = InternalEnforcer + Management API.
 */
export class ManagementEnforcer extends InternalEnforcer {
  /**
   * getAllSubjects gets the list of subjects that show up in the current policy.
   *
   * @return all the subjects in "p" policy rules. It actually collects the
   *         0-index elements of "p" policy rules. So make sure your subject
   *         is the 0-index element, like (sub, obj, act). Duplicates are removed.
   */
  public async getAllSubjects(): Promise<string[]> {
    return this.getAllNamedSubjects('p');
  }

  /**
   * getAllNamedSubjects gets the list of subjects that show up in the currentnamed policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @return all the subjects in policy rules of the ptype type. It actually
   *         collects the 0-index elements of the policy rules. So make sure
   *         your subject is the 0-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllNamedSubjects(ptype: string): Promise<string[]> {
    return this.model.getValuesForFieldInPolicy('p', ptype, 0);
  }

  /**
   * getAllObjects gets the list of objects that show up in the current policy.
   *
   * @return all the objects in "p" policy rules. It actually collects the
   *         1-index elements of "p" policy rules. So make sure your object
   *         is the 1-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllObjects(): Promise<string[]> {
    return this.getAllNamedObjects('p');
  }

  /**
   * getAllNamedObjects gets the list of objects that show up in the current named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @return all the objects in policy rules of the ptype type. It actually
   *         collects the 1-index elements of the policy rules. So make sure
   *         your object is the 1-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllNamedObjects(ptype: string): Promise<string[]> {
    return this.model.getValuesForFieldInPolicy('p', ptype, 1);
  }

  /**
   * getAllActions gets the list of actions that show up in the current policy.
   *
   * @return all the actions in "p" policy rules. It actually collects
   *         the 2-index elements of "p" policy rules. So make sure your action
   *         is the 2-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllActions(): Promise<string[]> {
    return this.getAllNamedActions('p');
  }

  /**
   * GetAllNamedActions gets the list of actions that show up in the current named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @return all the actions in policy rules of the ptype type. It actually
   *         collects the 2-index elements of the policy rules. So make sure
   *         your action is the 2-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllNamedActions(ptype: string): Promise<string[]> {
    return this.model.getValuesForFieldInPolicy('p', ptype, 2);
  }

  /**
   * getAllRoles gets the list of roles that show up in the current policy.
   *
   * @return all the roles in "g" policy rules. It actually collects
   *         the 1-index elements of "g" policy rules. So make sure your
   *         role is the 1-index element, like (sub, role).
   *         Duplicates are removed.
   */
  public async getAllRoles(): Promise<string[]> {
    return this.getAllNamedRoles('g');
  }

  /**
   * getAllNamedRoles gets the list of roles that show up in the current named policy.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @return all the subjects in policy rules of the ptype type. It actually
   *         collects the 0-index elements of the policy rules. So make
   *         sure your subject is the 0-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllNamedRoles(ptype: string): Promise<string[]> {
    return this.model.getValuesForFieldInPolicy('g', ptype, 1);
  }

  /**
   * getPolicy gets all the authorization rules in the policy.
   *
   * @return all the "p" policy rules.
   */
  public async getPolicy(): Promise<string[][]> {
    return this.getNamedPolicy('p');
  }

  /**
   * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
   *
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return the filtered "p" policy rules.
   */
  public async getFilteredPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<string[][]> {
    return this.getFilteredNamedPolicy('p', fieldIndex, ...fieldValues);
  }

  /**
   * getNamedPolicy gets all the authorization rules in the named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @return the "p" policy rules of the specified ptype.
   */
  public async getNamedPolicy(ptype: string): Promise<string[][]> {
    return this.model.getPolicy('p', ptype);
  }

  /**
   * getFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return the filtered "p" policy rules of the specified ptype.
   */
  public async getFilteredNamedPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<string[][]> {
    return this.model.getFilteredPolicy('p', ptype, fieldIndex, ...fieldValues);
  }

  /**
   * getGroupingPolicy gets all the role inheritance rules in the policy.
   *
   * @return all the "g" policy rules.
   */
  public async getGroupingPolicy(): Promise<string[][]> {
    return this.getNamedGroupingPolicy('g');
  }

  /**
   * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
   *
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value "" means not to match this field.
   * @return the filtered "g" policy rules.
   */
  public async getFilteredGroupingPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<string[][]> {
    return this.getFilteredNamedGroupingPolicy('g', fieldIndex, ...fieldValues);
  }

  /**
   * getNamedGroupingPolicy gets all the role inheritance rules in the policy.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @return the "g" policy rules of the specified ptype.
   */
  public async getNamedGroupingPolicy(ptype: string): Promise<string[][]> {
    return this.model.getPolicy('g', ptype);
  }

  /**
   * getFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return the filtered "g" policy rules of the specified ptype.
   */
  public async getFilteredNamedGroupingPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<string[][]> {
    return this.model.getFilteredPolicy('g', ptype, fieldIndex, ...fieldValues);
  }

  /**
   * hasPolicy determines whether an authorization rule exists.
   *
   * @param params the "p" policy rule, ptype "p" is implicitly used.
   * @return whether the rule exists.
   */
  public async hasPolicy(...params: string[]): Promise<boolean> {
    return this.hasNamedPolicy('p', ...params);
  }

  /**
   * hasNamedPolicy determines whether a named authorization rule exists.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param params the "p" policy rule.
   * @return whether the rule exists.
   */
  public async hasNamedPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.model.hasPolicy('p', ptype, params);
  }

  /**
   * addPolicy adds an authorization rule to the current policy.
   * If the rule already exists, the function returns false and the rule will not be added.
   * Otherwise the function returns true by adding the new rule.
   *
   * @param params the "p" policy rule, ptype "p" is implicitly used.
   * @return succeeds or not.
   */
  public async addPolicy(...params: string[]): Promise<boolean> {
    return this.addNamedPolicy('p', ...params);
  }

  /**
   * addPolicies adds authorization rules to the current policy.
   * If the rule already exists, the function returns false and the rules will not be added.
   * Otherwise the function returns true by adding the new rules.
   *
   * @param rules the "p" policy rules, ptype "p" is implicitly used.
   * @return succeeds or not.
   */
  public async addPolicies(rules: string[][]): Promise<boolean> {
    return this.addNamedPolicies('p', rules);
  }

  /**
   * addNamedPolicy adds an authorization rule to the current named policy.
   * If the rule already exists, the function returns false and the rule will not be added.
   * Otherwise the function returns true by adding the new rule.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param params the "p" policy rule.
   * @return succeeds or not.
   */
  public async addNamedPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.addPolicyInternal('p', ptype, params, true);
  }

  /**
   * addNamedPolicies adds authorization rules to the current named policy.
   * If the rule already exists, the function returns false and the rules will not be added.
   * Otherwise the function returns true by adding the new rules.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param rules the "p" policy rules.
   * @return succeeds or not.
   */
  public async addNamedPolicies(ptype: string, rules: string[][]): Promise<boolean> {
    return this.addPoliciesInternal('p', ptype, rules, true);
  }

  /**
   * addPoliciesEx adds authorization rules to the current policy.
   * If a rule already exists, the function will skip it and continue to add the remaining rules.
   * The function returns true if at least one rule was added successfully.
   *
   * @param rules the "p" policy rules, ptype "p" is implicitly used.
   * @return succeeds or not.
   */
  public async addPoliciesEx(rules: string[][]): Promise<boolean> {
    return this.addNamedPoliciesEx('p', rules);
  }

  /**
   * addNamedPoliciesEx adds authorization rules to the current named policy.
   * If a rule already exists, the function will skip it and continue to add the remaining rules.
   * The function returns true if at least one rule was added successfully.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param rules the "p" policy rules.
   * @return succeeds or not.
   */
  public async addNamedPoliciesEx(ptype: string, rules: string[][]): Promise<boolean> {
    return this.addPoliciesInternalEx('p', ptype, rules, true);
  }

  /**
   * updatePolicy updates an authorization rule from the current policy.
   * If the rule not exists, the function returns false.
   * Otherwise the function returns true by changing it to the new rule.
   *
   * @return succeeds or not.
   * @param oldRule the policy will be remove
   * @param newRule the policy will be added
   */
  public async updatePolicy(oldRule: string[], newRule: string[]): Promise<boolean> {
    return this.updateNamedPolicy('p', oldRule, newRule);
  }

  /**
   * updateNamedPolicy updates an authorization rule from the current named policy.
   * If the rule not exists, the function returns false.
   * Otherwise the function returns true by changing it to the new rule.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param oldRule the policy rule will be remove
   * @param newRule the policy rule will be added
   * @return succeeds or not.
   */
  public async updateNamedPolicy(ptype: string, oldRule: string[], newRule: string[]): Promise<boolean> {
    return this.updatePolicyInternal('p', ptype, oldRule, newRule, true);
  }

  /**
   * removePolicy removes an authorization rule from the current policy.
   *
   * @param params the "p" policy rule, ptype "p" is implicitly used.
   * @return succeeds or not.
   */
  public async removePolicy(...params: string[]): Promise<boolean> {
    return this.removeNamedPolicy('p', ...params);
  }

  /**
   * removePolicies removes an authorization rules from the current policy.
   *
   * @param rules the "p" policy rules, ptype "p" is implicitly used.
   * @return succeeds or not.
   */
  public async removePolicies(rules: string[][]): Promise<boolean> {
    return this.removeNamedPolicies('p', rules);
  }

  /**
   * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
   *
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return succeeds or not.
   */
  public async removeFilteredPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<boolean> {
    return this.removeFilteredNamedPolicy('p', fieldIndex, ...fieldValues);
  }

  /**
   * removeNamedPolicy removes an authorization rule from the current named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param params the "p" policy rule.
   * @return succeeds or not.
   */
  public async removeNamedPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.removePolicyInternal('p', ptype, params, true);
  }

  /**
   * removeNamedPolicies removes authorization rules from the current named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param rules the "p" policy rules.
   * @return succeeds or not.
   */
  public async removeNamedPolicies(ptype: string, rules: string[][]): Promise<boolean> {
    return this.removePoliciesInternal('p', ptype, rules, true);
  }

  /**
   * removeFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return succeeds or not.
   */
  public async removeFilteredNamedPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<boolean> {
    return this.removeFilteredPolicyInternal('p', ptype, fieldIndex, fieldValues, true);
  }

  /**
   * hasGroupingPolicy determines whether a role inheritance rule exists.
   *
   * @param params the "g" policy rule, ptype "g" is implicitly used.
   * @return whether the rule exists.
   */
  public async hasGroupingPolicy(...params: string[]): Promise<boolean> {
    return this.hasNamedGroupingPolicy('g', ...params);
  }

  /**
   * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param params the "g" policy rule.
   * @return whether the rule exists.
   */
  public async hasNamedGroupingPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.model.hasPolicy('g', ptype, params);
  }

  /**
   * addGroupingPolicy adds a role inheritance rule to the current policy.
   * If the rule already exists, the function returns false and the rule will not be added.
   * Otherwise the function returns true by adding the new rule.
   *
   * @param params the "g" policy rule, ptype "g" is implicitly used.
   * @return succeeds or not.
   */
  public async addGroupingPolicy(...params: string[]): Promise<boolean> {
    return this.addNamedGroupingPolicy('g', ...params);
  }

  /**
   * addGroupingPolicies adds a role inheritance rules to the current policy.
   * If the rule already exists, the function returns false and the rules will not be added.
   * Otherwise the function returns true by adding the new rules.
   *
   * @param rules the "g" policy rules, ptype "g" is implicitly used.
   * @return succeeds or not.
   */
  public async addGroupingPolicies(rules: string[][]): Promise<boolean> {
    return this.addNamedGroupingPolicies('g', rules);
  }

  /**
   * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
   * If the rule already exists, the function returns false and the rule will not be added.
   * Otherwise the function returns true by adding the new rule.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param params the "g" policy rule.
   * @return succeeds or not.
   */
  public async addNamedGroupingPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.addPolicyInternal('g', ptype, params, true);
  }

  /**
   * addNamedGroupingPolicies adds named role inheritance rules to the current policy.
   * If the rule already exists, the function returns false and the rules will not be added.
   * Otherwise the function returns true by adding the new rules.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param rules the "g" policy rule.
   * @return succeeds or not.
   */
  public async addNamedGroupingPolicies(ptype: string, rules: string[][]): Promise<boolean> {
    return this.addPoliciesInternal('g', ptype, rules, true);
  }

  /**
   * addGroupingPoliciesEx adds role inheritance rules to the current policy.
   * If a rule already exists, the function will skip it and continue to add the remaining rules.
   * The function returns true if at least one rule was added successfully.
   *
   * @param rules the "g" policy rules, ptype "g" is implicitly used.
   * @return succeeds or not.
   */
  public async addGroupingPoliciesEx(rules: string[][]): Promise<boolean> {
    return this.addNamedGroupingPoliciesEx('g', rules);
  }

  /**
   * addNamedGroupingPoliciesEx adds named role inheritance rules to the current policy.
   * If a rule already exists, the function will skip it and continue to add the remaining rules.
   * The function returns true if at least one rule was added successfully.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param rules the "g" policy rules.
   * @return succeeds or not.
   */
  public async addNamedGroupingPoliciesEx(ptype: string, rules: string[][]): Promise<boolean> {
    return this.addPoliciesInternalEx('g', ptype, rules, true);
  }

  /**
   * removeGroupingPolicy removes a role inheritance rule from the current policy.
   *
   * @param params the "g" policy rule, ptype "g" is implicitly used.
   * @return succeeds or not.
   */
  public async removeGroupingPolicy(...params: string[]): Promise<boolean> {
    return this.removeNamedGroupingPolicy('g', ...params);
  }

  /**
   * removeGroupingPolicies removes role inheritance rules from the current policy.
   *
   * @param rules the "g" policy rules, ptype "g" is implicitly used.
   * @return succeeds or not.
   */
  public async removeGroupingPolicies(rules: string[][]): Promise<boolean> {
    return this.removeNamedGroupingPolicies('g', rules);
  }

  /**
   * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
   *
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return succeeds or not.
   */
  public async removeFilteredGroupingPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<boolean> {
    return this.removeFilteredNamedGroupingPolicy('g', fieldIndex, ...fieldValues);
  }

  /**
   * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param params the "g" policy rule.
   * @return succeeds or not.
   */
  public async removeNamedGroupingPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.removePolicyInternal('g', ptype, params, true);
  }

  /**
   * removeNamedGroupingPolicies removes role inheritance rules from the current named policy.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param rules the "g" policy rules.
   * @return succeeds or not.
   */
  public async removeNamedGroupingPolicies(ptype: string, rules: string[][]): Promise<boolean> {
    return this.removePoliciesInternal('g', ptype, rules, true);
  }

  /**
   * removeFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return succeeds or not.
   */
  public async removeFilteredNamedGroupingPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<boolean> {
    return this.removeFilteredPolicyInternal('g', ptype, fieldIndex, fieldValues, true);
  }

  /**
   * UpdateGroupingPolicy updates an rule to the current named policy.
   *
   * @param oldRule the old rule.
   * @param newRule the new rule.
   * @return succeeds or not.
   */
  public async updateGroupingPolicy(oldRule: string[], newRule: string[]): Promise<boolean> {
    return this.updateNamedGroupingPolicy('g', oldRule, newRule);
  }

  /**
   * updateNamedGroupingPolicy updates an rule to the current named policy.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param oldRule the old rule.
   * @param newRule the new rule.
   * @return succeeds or not.
   */
  public async updateNamedGroupingPolicy(ptype: string, oldRule: string[], newRule: string[]): Promise<boolean> {
    return this.updatePolicyInternal('g', ptype, oldRule, newRule, true);
  }

  /**
   * addFunction adds a customized function.
   * @param name custom function name
   * @param func function
   */
  public async addFunction(name: string, func: MatchingFunction): Promise<void> {
    this.fm.addFunction(name, func);
  }
  public async selfAddPolicy(sec: string, ptype: string, rule: string[]): Promise<boolean> {
    return this.addPolicyWithoutNotify(sec, ptype, rule);
  }

  public async selfAddPolicies(sec: string, ptype: string, rules: string[][]): Promise<boolean> {
    return this.addPoliciesWithoutNotify(sec, ptype, rules);
  }

  public async selfRemovePolicy(sec: string, ptype: string, rule: string[]): Promise<boolean> {
    return this.removePolicyWithoutNotify(sec, ptype, rule);
  }

  public async selfRemovePolicies(sec: string, ptype: string, rules: string[][]): Promise<boolean> {
    return this.removePoliciesWithoutNotify(sec, ptype, rules);
  }

  public async selfRemoveFilteredPolicy(sec: string, ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<boolean> {
    return this.removeFilteredPolicyWithoutNotify(sec, ptype, fieldIndex, fieldValues);
  }

  public async selfUpdatePolicy(sec: string, ptype: string, oldRule: string[], newRule: string[]): Promise<boolean> {
    return this.updatePolicyWithoutNotify(sec, ptype, oldRule, newRule);
  }

  public async selfUpdatePolicies(sec: string, ptype: string, oldRules: string[][], newRules: string[][]): Promise<boolean> {
    return this.updatePoliciesWithoutNotify(sec, ptype, oldRules, newRules);
  }
}
