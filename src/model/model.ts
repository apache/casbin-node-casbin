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

import * as rbac from '../rbac';
import * as util from '../util';
import { Config, ConfigInterface } from '../config';
import { Assertion } from './assertion';
import { getLogger, logPrint } from '../log';
import { DefaultRoleManager } from '../rbac';
import { EffectExpress, FieldIndex } from '../constants';
import { FileSystem } from '../persist/fileSystem';
import { ValidatorEnforcer } from '../validatorEnforcer';

const defaultDomain = '';
const defaultSeparator = '::';

export const sectionNameMap: { [index: string]: string } = {
  r: 'request_definition',
  p: 'policy_definition',
  g: 'role_definition',
  e: 'policy_effect',
  m: 'matchers',
};

export enum PolicyOp {
  PolicyAdd,
  PolicyRemove,
}

export const requiredSections = ['r', 'p', 'e', 'm'];

export class Model {
  // Model represents the whole access control model.
  // Mest-map is the collection of assertions, can be "r", "p", "g", "e", "m".
  public model: Map<string, Map<string, Assertion>>;

  /**
   * constructor is the constructor for Model.
   */
  constructor() {
    this.model = new Map<string, Map<string, Assertion>>();
  }

  private loadAssertion(cfg: ConfigInterface, sec: string, key: string): boolean {
    const secName = sectionNameMap[sec];
    const value = cfg.getString(`${secName}::${key}`);
    return this.addDef(sec, key, value);
  }

  private getKeySuffix(i: number): string {
    if (i === 1) {
      return '';
    }

    return i.toString();
  }

  private loadSection(cfg: ConfigInterface, sec: string): void {
    let i = 1;
    for (;;) {
      if (!this.loadAssertion(cfg, sec, sec + this.getKeySuffix(i))) {
        break;
      } else {
        i++;
      }
    }
  }

  // addDef adds an assertion to the model.
  public addDef(sec: string, key: string, value: string): boolean {
    if (value === '') {
      return false;
    }

    const ast = new Assertion();
    ast.key = key;
    ast.value = value;
    ast.fieldIndexMap = new Map<string, number>();

    if (sec === 'r' || sec === 'p') {
      const tokens = value.split(',').map((n) => n.trim());

      for (let i = 0; i < tokens.length; i++) {
        tokens[i] = key + '_' + tokens[i];
      }

      ast.tokens = tokens;
    } else if (sec === 'm') {
      const stringArguments = value.match(/\"(.*?)\"/g) || [];

      stringArguments.forEach((n, index) => {
        value = value.replace(n, `$<${index}>`);
      });

      value = util.escapeAssertion(value);

      stringArguments.forEach((n, index) => {
        value = value.replace(`$<${index}>`, n);
      });

      ValidatorEnforcer.validateMatcherOperators(value);

      ast.value = value;
    } else {
      ast.value = util.escapeAssertion(value);
    }

    const nodeMap = this.model.get(sec);

    if (nodeMap) {
      nodeMap.set(key, ast);
    } else {
      const assertionMap = new Map<string, Assertion>();
      assertionMap.set(key, ast);
      this.model.set(sec, assertionMap);
    }

    return true;
  }

  /**
   * loadModel loads the model from model CONF file.
   * @param path the model file path
   * @param fs {@link FileSystem}
   * @deprecated {@link loadModelFromFile}
   */
  public loadModel(path: string, fs?: FileSystem): void {
    this.loadModelFromFile(path, fs);
  }

  /**
   * loadModelFromFile loads the model from model CONF file.
   * @param path the model file path
   * @param fs {@link FileSystem}
   */
  public loadModelFromFile(path: string, fs?: FileSystem): void {
    const cfg = Config.newConfigFromFile(path, fs);

    this.loadModelFromConfig(cfg);
  }

  // loadModelFromText loads the model from the text.
  public loadModelFromText(text: string): void {
    const cfg = Config.newConfigFromText(text);

    this.loadModelFromConfig(cfg);
  }

  public loadModelFromConfig(cfg: ConfigInterface): void {
    for (const s in sectionNameMap) {
      this.loadSection(cfg, s);
    }

    ValidatorEnforcer.validateRequiredSections(this.model);
  }

  private hasSection(sec: string): boolean {
    return this.model.get(sec) !== undefined;
  }

  // printModel prints the model to the log.
  public printModel(): void {
    logPrint('Model:');
    this.model.forEach((value, key) => {
      value.forEach((ast, astKey) => {
        logPrint(`${key}.${astKey}: ${ast.value}`);
      });
    });
  }

  // buildIncrementalRoleLinks provides incremental build the role inheritance relations.
  public async buildIncrementalRoleLinks(rm: rbac.RoleManager, op: PolicyOp, sec: string, ptype: string, rules: string[][]): Promise<void> {
    if (sec === 'g') {
      await this.model.get(sec)?.get(ptype)?.buildIncrementalRoleLinks(rm, op, rules);
    }
  }

  // buildRoleLinks initializes the roles in RBAC.
  public async buildRoleLinks(rmMap: Map<string, rbac.RoleManager>): Promise<void> {
    const astMap = this.model.get('g');
    if (!astMap) {
      return;
    }
    for (const key of astMap.keys()) {
      const ast = astMap.get(key);
      let rm = rmMap.get(key);
      if (!rm) {
        rm = new DefaultRoleManager(10);
        rmMap.set(key, rm);
      }
      await ast?.buildRoleLinks(rm);
    }
  }

  // clearPolicy clears all current policy.
  public clearPolicy(): void {
    this.model.forEach((value, key) => {
      if (key === 'p' || key === 'g') {
        value.forEach((ast) => {
          ast.policy = [];
        });
      }
    });
  }

  // getPolicy gets all rules in a policy.
  public getPolicy(sec: string, key: string): string[][] {
    const policy: string[][] = [];

    const ast = this.model.get(sec)?.get(key);
    if (ast) {
      policy.push(...ast.policy);
    }
    return policy;
  }

  // hasPolicy determines whether a model has the specified policy rule.
  public hasPolicy(sec: string, key: string, rule: string[]): boolean {
    const ast = this.model.get(sec)?.get(key);
    if (!ast) {
      return false;
    }
    return ast.policy.some((n: string[]) => util.arrayEquals(n, rule));
  }

  // addPolicy adds a policy rule to the model.
  public addPolicy(sec: string, key: string, rule: string[]): boolean {
    if (!this.hasPolicy(sec, key, rule)) {
      const ast = this.model.get(sec)?.get(key);
      if (!ast) {
        return false;
      }

      const policy = ast.policy;
      const tokens = ast.tokens;

      const priorityIndex = tokens.indexOf(`${key}_priority`);

      if (priorityIndex !== -1) {
        const priorityRule = rule[priorityIndex];
        const insertIndex = policy.findIndex((oneRule) => oneRule[priorityIndex] >= priorityRule);

        if (priorityIndex === -1) {
          policy.push(rule);
        } else {
          policy.splice(insertIndex, 0, rule);
        }
      } else {
        policy.push(rule);
      }
      return true;
    }

    return false;
  }

  // addPolicies adds policy rules to the model.
  public addPolicies(sec: string, ptype: string, rules: string[][]): [boolean, string[][]] {
    const ast = this.model.get(sec)?.get(ptype);
    if (!ast) {
      return [false, []];
    }

    for (const rule of rules) {
      if (this.hasPolicy(sec, ptype, rule)) {
        return [false, []];
      }
    }

    const priorityFlag = ast.tokens.indexOf(`${ptype}_priority`) !== -1;

    if (priorityFlag) {
      rules.forEach((rule) => {
        this.addPolicy(sec, ptype, rule);
      });
    } else {
      ast.policy = ast.policy.concat(rules);
    }

    return [true, rules];
  }

  // updatePolicy updates a policy from the model
  public updatePolicy(sec: string, ptype: string, oldRule: string[], newRule: string[]): boolean {
    const ast = this.model.get(sec)?.get(ptype);
    if (!ast) {
      return false;
    }

    const index = ast.policy.findIndex((r) => util.arrayEquals(r, oldRule));
    if (index === -1) {
      return false;
    }

    const priorityIndex = ast.tokens.indexOf(`${ptype}_priority`);

    if (priorityIndex !== -1) {
      ValidatorEnforcer.validatePolicyPriority(oldRule, newRule, priorityIndex);
      ast.policy[index] = newRule;
    } else {
      ast.policy[index] = newRule;
    }

    return true;
  }

  // removePolicy removes a policy rule from the model.
  public removePolicy(sec: string, key: string, rule: string[]): boolean {
    if (this.hasPolicy(sec, key, rule)) {
      const ast = this.model.get(sec)?.get(key);
      if (!ast) {
        return false;
      }
      ast.policy = ast.policy.filter((r) => !util.arrayEquals(rule, r));
      return true;
    }

    return false;
  }

  // removePolicies removes policy rules from the model.
  public removePolicies(sec: string, ptype: string, rules: string[][]): [boolean, string[][]] {
    const effects: string[][] = [];
    const ast = this.model.get(sec)?.get(ptype);
    if (!ast) {
      return [false, []];
    }

    for (const rule of rules) {
      if (!this.hasPolicy(sec, ptype, rule)) {
        return [false, []];
      }
    }

    for (const rule of rules) {
      ast.policy = ast.policy.filter((r: string[]) => {
        const equals = util.arrayEquals(rule, r);
        if (equals) {
          effects.push(r);
        }
        return !equals;
      });
    }

    return [true, effects];
  }

  // getFilteredPolicy gets rules based on field filters from a policy.
  public getFilteredPolicy(sec: string, key: string, fieldIndex: number, ...fieldValues: string[]): string[][] {
    const res: string[][] = [];
    const ast = this.model.get(sec)?.get(key);
    if (!ast) {
      return res;
    }
    for (const rule of ast.policy) {
      let matched = true;
      for (let i = 0; i < fieldValues.length; i++) {
        const fieldValue = fieldValues[i];
        if (fieldValue !== '' && rule[fieldIndex + i] !== fieldValue) {
          matched = false;
          break;
        }
      }

      if (matched) {
        res.push(rule);
      }
    }

    return res;
  }

  // removeFilteredPolicy removes policy rules based on field filters from the model.
  public removeFilteredPolicy(sec: string, key: string, fieldIndex: number, ...fieldValues: string[]): [boolean, string[][]] {
    const res = [];
    const effects: string[][] = [];
    let bool = false;
    if (fieldValues.length === 0) {
      return [false, effects];
    }
    const ast = this.model.get(sec)?.get(key);
    if (!ast) {
      return [false, []];
    }
    for (const rule of ast.policy) {
      let matched = true;
      for (let i = 0; i < fieldValues.length; i++) {
        const fieldValue = fieldValues[i];
        if (fieldValue !== '' && rule[fieldIndex + i] !== fieldValue) {
          matched = false;
          break;
        }
      }

      if (matched) {
        bool = true;
        effects.push(rule);
      } else {
        res.push(rule);
      }
    }

    if (effects.length !== 0) {
      ast.policy = res;
    }

    return [bool, effects];
  }

  // getValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
  public getValuesForFieldInPolicy(sec: string, key: string, fieldIndex: number): string[] {
    const values: string[] = [];
    const ast = this.model.get(sec)?.get(key);
    if (!ast) {
      return values;
    }
    return util.arrayRemoveDuplicates(ast.policy.map((n: string[]) => n[fieldIndex]));
  }

  // getValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all ptypes, duplicated values are removed.
  public getValuesForFieldInPolicyAllTypes(sec: string, fieldIndex: number): string[] {
    const values: string[] = [];

    const ast = this.model.get(sec);
    if (!ast) {
      return values;
    }

    for (const ptype of ast.keys()) {
      values.push(...this.getValuesForFieldInPolicy(sec, ptype, fieldIndex));
    }

    return util.arrayRemoveDuplicates(values);
  }

  // printPolicy prints the policy to log.
  public printPolicy(): void {
    if (!getLogger().isEnable()) {
      return;
    }
    logPrint('Policy:');
    this.model.forEach((map, key) => {
      if (key === 'p' || key === 'g') {
        map.forEach((ast) => {
          logPrint(`key, : ${ast.value}, : , ${ast.policy}`);
        });
      }
    });
  }

  /**
   * return the field index in fieldMap, if no this field in fieldMap, add it.
   */
  public getFieldIndex(ptype: string, field: string): number {
    const assertion = this.model.get('p')?.get(ptype);
    if (!assertion) {
      return -1;
    }

    let index = assertion.fieldIndexMap.get(field);
    if (index) {
      return index;
    }

    const pattern = ptype + '_' + field;
    index = -1;
    for (let i = 0; i < assertion.tokens.length; i++) {
      if (assertion.tokens[i] === pattern) {
        index = i;
        break;
      }
    }
    if (index === -1) {
      return index;
    }
    assertion.fieldIndexMap.set(field, index);
    return index;
  }

  /**
   * sort policies by subject hieraichy
   */
  public sortPoliciesBySubjectHierarchy(): void {
    if (this.model.get('e')?.get('e')?.value !== EffectExpress.SUBJECT_PRIORITY) {
      return;
    }

    this.model.get('p')?.forEach((assertion, ptype) => {
      const domainIndex = this.getFieldIndex(ptype, FieldIndex.Domain);
      const subIndex = this.getFieldIndex(ptype, FieldIndex.Subject);
      // eslint-disable-next-line
      const subjectHierarchyMap = this.getSubjectHierarchyMap(this.model.get('g')!.get('g')!.policy);

      assertion.policy.sort((policyA, policyB) => {
        const domainA = domainIndex === -1 ? defaultDomain : policyA[domainIndex];
        const domainB = domainIndex === -1 ? defaultDomain : policyB[domainIndex];
        // eslint-disable-next-line
        const priorityA = subjectHierarchyMap.get(this.getNameWithDomain(domainA, policyA[subIndex]))!;
        // eslint-disable-next-line
        const priorityB = subjectHierarchyMap.get(this.getNameWithDomain(domainB, policyB[subIndex]))!;
        return priorityB - priorityA;
      });
    });
  }

  /**
   * Calculate the priority of each policy store in Map<string, number>
   */
  getSubjectHierarchyMap(groupPolicies: string[][]): Map<string, number> {
    const subjectHierarchyMap = new Map<string, number>();
    if (!groupPolicies) {
      return subjectHierarchyMap;
    }

    const policyMap = new Map<string, string>();
    let domain = defaultDomain;

    groupPolicies.forEach((policy) => {
      if (policy.length !== 2) domain = policy[this.getFieldIndex('p', FieldIndex.Domain)];
      const child = this.getNameWithDomain(domain, policy[this.getFieldIndex('p', FieldIndex.Subject)]);
      const parent = this.getNameWithDomain(domain, policy[this.getFieldIndex('p', FieldIndex.Object)]);
      policyMap.set(child, parent);
      if (!subjectHierarchyMap.has(child)) {
        subjectHierarchyMap.set(child, 0);
      }
      if (!subjectHierarchyMap.has(parent)) {
        subjectHierarchyMap.set(parent, 0);
      }
      subjectHierarchyMap.set(child, 1);
    });

    const set = new Set<string>();
    subjectHierarchyMap.forEach((_, key) => {
      if (subjectHierarchyMap.get(key) !== 0) set.add(key);
    });
    while (set.size !== 0) {
      for (const child of set.values()) {
        this.findHierarchy(policyMap, subjectHierarchyMap, set, child);
      }
    }
    return subjectHierarchyMap;
  }

  findHierarchy(policyMap: Map<string, string>, subjectHierarchyMap: Map<string, number>, set: Set<string>, child: string): void {
    set.delete(child);
    // eslint-disable-next-line
    const parent = policyMap.get(child)!;

    if (set.has(parent)) {
      this.findHierarchy(policyMap, subjectHierarchyMap, set, parent);
    }
    // eslint-disable-next-line
    subjectHierarchyMap.set(child, subjectHierarchyMap.get(parent)! + 10);
  }

  /**
   * get full name with domain
   */
  getNameWithDomain(domain: string, name: string): string {
    return domain + defaultSeparator + name;
  }
}

/**
 * newModel creates a model.
 */
export function newModel(...text: string[]): Model {
  const m = new Model();

  ValidatorEnforcer.validateModelParameters(text.length);

  if (text.length === 2) {
    if (text[0] !== '') {
      m.loadModelFromFile(text[0]);
    }
  } else if (text.length === 1) {
    m.loadModelFromText(text[0]);
  }

  return m;
}

/**
 * newModelFromFile creates a model from a .CONF file.
 */
export function newModelFromFile(path: string, fs?: FileSystem): Model {
  const m = new Model();
  if (path) {
    m.loadModelFromFile(path, fs);
  }
  return m;
}

/**
 * newModelFromString creates a model from a string which contains model text.
 */
export function newModelFromString(text: string): Model {
  const m = new Model();
  m.loadModelFromText(text);
  return m;
}
