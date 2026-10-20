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

import { compile, compileAsync, addBinaryOp } from '@casbin/expression-eval';

import { DefaultEffector, Effect, Effector } from './effect';
import { FunctionMap, Model, newModelFromFile, PolicyOp } from './model';
import { Adapter, FilteredAdapter, Watcher, BatchAdapter, UpdatableAdapter, WatcherEx } from './persist';
import { DefaultRoleManager, RoleManager } from './rbac';
import { EnforceContext } from './enforceContext';

import {
  escapeAssertion,
  generateGFunction,
  generateSyncedGFunction,
  getEvalValue,
  keyMatchFunc,
  hasEval,
  replaceEval,
  generatorRunSync,
  generatorRunAsync,
  customIn,
  bracketCompatible,
  removeComments,
} from './util';
import { getLogger, logPrint } from './log';
import { MatchingFunc } from './rbac';
import { FileSystem, getDefaultFileSystem } from './persist';

type Matcher = ((context: any) => Promise<any>) | ((context: any) => any);

type EnforceResult = Generator<(boolean | [boolean, string[]]) | Promise<boolean | [boolean, string[]]>>;

/**
 * CoreEnforcer defines the core functionality of an enforcer.
 */
export class CoreEnforcer {
  protected modelPath: string;
  protected model: Model;
  protected fm: FunctionMap = FunctionMap.loadFunctionMap();
  protected eft: Effector = new DefaultEffector();
  private matcherMap: Map<string, Matcher> = new Map();
  private defaultEnforceContext: EnforceContext = new EnforceContext('r', 'p', 'e', 'm');

  protected adapter: UpdatableAdapter | FilteredAdapter | Adapter | BatchAdapter;
  protected watcher: Watcher | null = null;
  protected watcherEx: WatcherEx | null = null;
  protected rmMap: Map<string, RoleManager>;

  protected enabled = true;
  protected autoSave = true;
  protected autoBuildRoleLinks = true;
  protected autoNotifyWatcher = true;
  protected acceptJsonRequest = false;
  protected fs?: FileSystem;

  /**
   * setFileSystem sets a file system to read the model file or the policy file.
   * @param fs {@link FileSystem}
   */
  public setFileSystem(fs: FileSystem): void {
    this.fs = fs;
  }

  /**
   * getFileSystem gets the file system,
   */
  public getFileSystem(): FileSystem | undefined {
    return this.fs;
  }

  private getExpression(asyncCompile: boolean, exp: string): Matcher {
    const matcherKey = `${asyncCompile ? 'ASYNC[' : 'SYNC['}${exp}]`;

    addBinaryOp('in', 6, customIn);

    let expression = this.matcherMap.get(matcherKey);
    if (!expression) {
      exp = bracketCompatible(exp);
      expression = asyncCompile ? compileAsync(exp) : compile(exp);
      this.matcherMap.set(matcherKey, expression);
    }
    return expression;
  }

  /**
   * loadModel reloads the model from the model CONF file.
   * Because the policy is attached to a model,
   * so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
   */
  public loadModel(): void {
    this.model = newModelFromFile(this.modelPath, this.fs);
    this.model.printModel();
  }

  /**
   * getModel gets the current model.
   *
   * @return the model of the enforcer.
   */
  public getModel(): Model {
    return this.model;
  }

  /**
   * setModel sets the current model.
   *
   * @param m the model.
   */
  public setModel(m: Model): void {
    this.model = m;
  }

  /**
   * getAdapter gets the current adapter.
   *
   * @return the adapter of the enforcer.
   */
  public getAdapter(): Adapter {
    return this.adapter;
  }

  /**
   * setAdapter sets the current adapter.
   *
   * @param adapter the adapter.
   */
  public setAdapter(adapter: Adapter): void {
    this.adapter = adapter;
  }

  /**
   * setWatcher sets the current watcher.
   *
   * @param watcher the watcher.
   */
  public setWatcher(watcher: Watcher): void {
    this.watcher = watcher;
    watcher.setUpdateCallback(async () => await this.loadPolicy());
  }

  /**
   * setWatcherEx sets the current watcherEx.
   *
   * @param watcherEx the watcherEx.
   */
  public setWatcherEx(watcherEx: WatcherEx): void {
    this.watcherEx = watcherEx;
  }

  /**
   * setRoleManager sets the current role manager.
   *
   * @param rm the role manager.
   */
  public setRoleManager(rm: RoleManager): void {
    this.rmMap.set('g', rm);
  }

  /**
   * setRoleManager sets the role manager for the named policy.
   *
   * @param ptype the named policy.
   * @param rm the role manager.
   */
  public setNamedRoleManager(ptype: string, rm: RoleManager): void {
    this.rmMap.set(ptype, rm);
  }

  /**
   * getRoleManager gets the current role manager.
   */
  public getRoleManager(): RoleManager {
    return <RoleManager>this.rmMap.get('g');
  }

  /**
   * getNamedRoleManager gets role manager by name.
   */
  public getNamedRoleManager(name: string): RoleManager | undefined {
    return this.rmMap.get(name);
  }

  /**
   * setEffector sets the current effector.
   *
   * @param eft the effector.
   */
  public setEffector(eft: Effector): void {
    this.eft = eft;
  }

  /**
   * clearPolicy clears all policy.
   */
  public clearPolicy(): void {
    this.model.clearPolicy();
  }

  public initRmMap(): void {
    this.rmMap = new Map<string, RoleManager>();
    const rm = this.model.model.get('g');
    if (rm) {
      for (const [ptype, ast] of rm) {
        const roleManager = new DefaultRoleManager(10);
        this.rmMap.set(ptype, roleManager);
        const count = (ast.value.match(/_/g) || []).length - ast.paramsTokens.length;
        if (count > 2 && this.usesKeyMatchForDomain()) {
          roleManager.addDomainMatchingFunc(keyMatchFunc);
        }
      }
    }
  }

  private usesKeyMatchForDomain(): boolean {
    const rDomainToken = this.model.model.get('r')?.get('r')?.tokens[1];
    const pDomainToken = this.model.model.get('p')?.get('p')?.tokens[1];
    if (!rDomainToken || !pDomainToken) {
      return false;
    }
    const matcher = this.model.model.get('m')?.get('m')?.value ?? '';
    return matcher.includes(`keyMatch(${rDomainToken}, ${pDomainToken})`);
  }

  public sortPolicies(): void {
    this.model.model.get('p')?.forEach((value, key) => {
      const policy = value.policy;
      const tokens = value.tokens;
      if (policy && tokens) {
        const priorityIndex = tokens.indexOf(`${key}_priority`);
        if (priorityIndex !== -1) {
          policy.sort((a, b) => {
            return parseInt(a[priorityIndex], 10) - parseInt(b[priorityIndex], 10);
          });
        }
      }
    });
  }

  /**
   * loadPolicy reloads the policy from file/database.
   */
  public async loadPolicy(): Promise<void> {
    this.model.clearPolicy();
    await this.adapter.loadPolicy(this.model);

    this.sortPolicies();
    this.model.sortPoliciesBySubjectHierarchy();

    if (this.autoBuildRoleLinks) {
      await this.buildRoleLinksInternal();
    }
  }

  /**
   * loadFilteredPolicy reloads a filtered policy from file/database.
   *
   * @param filter the filter used to specify which type of policy should be loaded.
   */
  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  public async loadFilteredPolicy(filter: any): Promise<boolean> {
    this.model.clearPolicy();

    this.sortPolicies();
    this.model.sortPoliciesBySubjectHierarchy();

    return this.loadIncrementalFilteredPolicy(filter);
  }

  /**
   * LoadIncrementalFilteredPolicy append a filtered policy from file/database.
   *
   * @param filter the filter used to specify which type of policy should be appended.
   */
  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  public async loadIncrementalFilteredPolicy(filter: any): Promise<boolean> {
    if ('isFiltered' in this.adapter) {
      await this.adapter.loadFilteredPolicy(this.model, filter);
    } else {
      throw new Error('filtered policies are not supported by this adapter');
    }

    this.sortPolicies();

    if (this.autoBuildRoleLinks) {
      await this.buildRoleLinksInternal();
    }
    return true;
  }

  /**
   * isFiltered returns true if the loaded policy has been filtered.
   *
   * @return if the loaded policy has been filtered.
   */
  public isFiltered(): boolean {
    if ('isFiltered' in this.adapter) {
      return this.adapter.isFiltered();
    }
    return false;
  }

  /**
   * savePolicy saves the current policy (usually after changed with
   * Casbin API) back to file/database.
   */
  public async savePolicy(): Promise<boolean> {
    if (this.isFiltered()) {
      throw new Error('Cannot save a filtered policy');
    }
    const flag = await this.adapter.savePolicy(this.model);
    if (!flag) {
      return false;
    }
    if (this.watcherEx) {
      return await this.watcherEx.updateForSavePolicy(this.model);
    } else if (this.watcher) {
      return await this.watcher.update();
    }
    return true;
  }

  /**
   * enableEnforce changes the enforcing state of Casbin, when Casbin is
   * disabled, all access will be allowed by the enforce() function.
   *
   * @param enable whether to enable the enforcer.
   */
  public enableEnforce(enable: boolean): void {
    this.enabled = enable;
  }

  /**
   * enableLog changes whether to print Casbin log to the standard output.
   *
   * @param enable whether to enable Casbin's log.
   */
  public enableLog(enable: boolean): void {
    getLogger().enableLog(enable);
  }

  /**
   * enableAutoSave controls whether to save a policy rule automatically to
   * the adapter when it is added or removed.
   *
   * @param autoSave whether to enable the AutoSave feature.
   */
  public enableAutoSave(autoSave: boolean): void {
    this.autoSave = autoSave;
  }

  /**
   * enableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
   * @param enable whether to enable the AutoNotifyWatcher feature.
   */
  public enableAutoNotifyWatcher(enable: boolean): void {
    this.autoNotifyWatcher = enable;
  }

  /**
   * enableAcceptJsonRequest determines whether to attempt parsing request args as JSON
   *
   * @param enable whether to attempt parsing request args as JSON
   */
  public enableAcceptJsonRequest(enable: boolean): void {
    this.acceptJsonRequest = enable;
  }

  /**
   * enableAutoBuildRoleLinks controls whether to save a policy rule
   * automatically to the adapter when it is added or removed.
   *
   * @param autoBuildRoleLinks whether to automatically build the role links.
   */
  public enableAutoBuildRoleLinks(autoBuildRoleLinks: boolean): void {
    this.autoBuildRoleLinks = autoBuildRoleLinks;
  }

  /**
   * add matching function to RoleManager by ptype
   * @param ptype g
   * @param fn the function will be added
   */
  public async addNamedMatchingFunc(ptype: string, fn: MatchingFunc): Promise<void> {
    const rm = this.rmMap.get(ptype);
    if (rm) {
      return await (<DefaultRoleManager>rm).addMatchingFunc(fn);
    }

    throw Error('Target ptype not found.');
  }

  /**
   * add domain matching function to RoleManager by ptype
   * @param ptype g
   * @param fn the function will be added
   */
  public async addNamedDomainMatchingFunc(ptype: string, fn: MatchingFunc): Promise<void> {
    const rm = this.rmMap.get(ptype);
    if (rm) {
      return await (<DefaultRoleManager>rm).addDomainMatchingFunc(fn);
    }
  }

  /**
   * buildRoleLinks manually rebuild the role inheritance relations.
   */
  public async buildRoleLinks(): Promise<void> {
    return this.buildRoleLinksInternal();
  }

  /**
   * buildIncrementalRoleLinks provides incremental build the role inheritance relations.
   * @param op policy operation
   * @param ptype g
   * @param rules policies
   */
  public async buildIncrementalRoleLinks(op: PolicyOp, ptype: string, rules: string[][]): Promise<void> {
    let rm = this.rmMap.get(ptype);
    if (!rm) {
      rm = new DefaultRoleManager(10);
      this.rmMap.set(ptype, rm);
    }
    await this.model.buildIncrementalRoleLinks(rm, op, 'g', ptype, rules);
  }

  protected async buildRoleLinksInternal(): Promise<void> {
    for (const rm of this.rmMap.values()) {
      await rm.clear();
      await this.model.buildRoleLinks(this.rmMap);
    }
  }

  private *privateEnforce(
    asyncCompile = true,
    explain = false,
    matcher: string,
    enforceContext: EnforceContext = new EnforceContext('r', 'p', 'e', 'm'),
    ...rvals: any[]
  ): EnforceResult {
    if (!this.enabled) {
      return true;
    }

    let explainIndex = -1;

    const functions: { [key: string]: any } = {};
    this.fm.getFunctions().forEach((value: any, key: string) => {
      functions[key] = value;
    });

    const astMap = this.model.model.get('g');

    astMap?.forEach((value, key) => {
      const rm = value.rm;
      functions[key] = asyncCompile ? generateGFunction(rm) : generateSyncedGFunction(rm);
    });

    let expString;

    if (!matcher) {
      expString = this.model.model.get('m')?.get(enforceContext.mType)?.value;
    } else {
      expString = removeComments(escapeAssertion(matcher));
    }

    if (!expString) {
      throw new Error('Unable to find matchers in model');
    }

    const effectExpr = this.model.model.get('e')?.get(enforceContext.eType)?.value;
    if (!effectExpr) {
      throw new Error('Unable to find policy_effect in model');
    }

    const HasEval: boolean = hasEval(expString);
    let expression: Matcher | undefined = undefined;

    const p = this.model.model.get('p')?.get(enforceContext.pType);
    const policy = p?.policy ? [...p.policy] : [];
    const policyLen = policy.length;

    const rTokens = this.model.model.get('r')?.get(enforceContext.rType)?.tokens;
    const rTokensLen = rTokens?.length;

    const effectStream = this.eft.newStream(effectExpr);

    if (policyLen && policyLen !== 0 && expString.includes(`${enforceContext.pType}_`)) {
      for (let i = 0; i < policyLen; i++) {
        const parameters: { [key: string]: any } = {};

        if (rTokens?.length !== rvals.length) {
          throw new Error(`invalid request size: expected ${rTokensLen}, got ${rvals.length}, rvals: ${rvals}"`);
        }

        if (this.acceptJsonRequest) {
          // Attempt to parse each request parameter as JSON; continue with string if failed
          rTokens.forEach((token, j) => {
            try {
              parameters[token] = JSON.parse(rvals[j]);
            } catch {
              parameters[token] = rvals[j];
            }
          });
        } else {
          rTokens.forEach((token, j) => {
            parameters[token] = rvals[j];
          });
        }

        p?.tokens.forEach((token, j) => {
          parameters[token] = policy[i][j];
        });

        if (HasEval) {
          const ruleNames: string[] = getEvalValue(expString);
          let expWithRule = expString;
          for (const ruleName of ruleNames) {
            if (ruleName in parameters) {
              const rule = escapeAssertion(parameters[ruleName]);
              expWithRule = replaceEval(expWithRule, ruleName, rule);
            } else {
              throw new Error(`${ruleName} not in ${parameters}`);
            }
          }
          expression = this.getExpression(asyncCompile, expWithRule);
        } else {
          if (expression === undefined) {
            expression = this.getExpression(asyncCompile, expString);
          }
        }

        const context = { ...parameters, ...functions };
        const result = asyncCompile ? yield expression(context) : expression(context);

        let eftRes: Effect;
        switch (typeof result) {
          case 'boolean':
            eftRes = result ? Effect.Allow : Effect.Indeterminate;
            break;
          case 'number':
            if (result === 0) {
              eftRes = Effect.Indeterminate;
            } else {
              eftRes = result;
            }
            break;
          case 'string':
            if (result === '') {
              eftRes = Effect.Indeterminate;
            } else {
              eftRes = Effect.Allow;
            }
            break;
          default:
            throw new Error('matcher result should only be of type boolean, number, or string');
        }

        const eft = parameters[`${enforceContext.pType}_eft`];
        if (eft && eftRes === Effect.Allow) {
          if (eft === 'allow') {
            eftRes = Effect.Allow;
          } else if (eft === 'deny') {
            eftRes = Effect.Deny;
          } else {
            eftRes = Effect.Indeterminate;
          }
        }

        const [res, rec, done] = effectStream.pushEffect(eftRes);

        if (rec) {
          explainIndex = i;
        }

        if (done) {
          break;
        }
      }
    } else {
      explainIndex = 0;

      const parameters: { [key: string]: any } = {};

      rTokens?.forEach((token, j): void => {
        parameters[token] = rvals[j];
      });

      p?.tokens?.forEach((token) => {
        parameters[token] = '';
      });

      expression = this.getExpression(asyncCompile, expString);
      const context = { ...parameters, ...functions };
      const result = asyncCompile ? yield expression(context) : expression(context);

      if (result) {
        effectStream.pushEffect(Effect.Allow);
      } else {
        effectStream.pushEffect(Effect.Indeterminate);
      }
    }

    const res = effectStream.current();

    // only generate the request --> result string if the message
    // is going to be logged.
    if (getLogger().isEnable()) {
      let reqStr = 'Request: ';
      for (let i = 0; i < rvals.length; i++) {
        if (i !== rvals.length - 1) {
          reqStr += `${rvals[i]}, `;
        } else {
          reqStr += rvals[i];
        }
      }
      reqStr += ` ---> ${res}`;
      logPrint(reqStr);
    }

    if (explain) {
      if (explainIndex === -1) {
        return [res, []];
      }
      return [res, policy[explainIndex] || []];
    }

    return res;
  }

  /**
   * If the matchers does not contain an asynchronous method, call it faster.
   *
   * enforceSync decides whether a "subject" can access a "object" with
   * the operation "action", input parameters are usually: (sub, obj, act).
   *
   * @param rvals the request needs to be mediated, usually an array
   *              of strings, can be class instances if ABAC is used.
   * @return whether to allow the request.
   */
  public enforceSync(...rvals: any[]): boolean {
    if (rvals[0] instanceof EnforceContext) {
      const enforceContext: EnforceContext = rvals.shift();
      return generatorRunSync(this.privateEnforce(false, false, '', enforceContext, ...rvals));
    }
    return generatorRunSync(this.privateEnforce(false, false, '', this.defaultEnforceContext, ...rvals));
  }

  /**
   * If the matchers does not contain an asynchronous method, call it faster.
   *
   * enforceSync decides whether a "subject" can access a "object" with
   * the operation "action", input parameters are usually: (sub, obj, act).
   *
   * @param rvals the request needs to be mediated, usually an array
   *              of strings, can be class instances if ABAC is used.
   * @return whether to allow the request and the reason rule.
   */
  public enforceExSync(...rvals: any[]): [boolean, string[]] {
    if (rvals[0] instanceof EnforceContext) {
      const enforceContext: EnforceContext = rvals.shift();
      return generatorRunSync(this.privateEnforce(false, true, '', enforceContext, ...rvals));
    }
    return generatorRunSync(this.privateEnforce(false, true, '', this.defaultEnforceContext, ...rvals));
  }

  /**
   * Same as enforceSync. To be removed.
   */
  public enforceWithSyncCompile(...rvals: any[]): boolean {
    return this.enforceSync(...rvals);
  }

  /**
   * enforce decides whether a "subject" can access a "object" with
   * the operation "action", input parameters are usually: (sub, obj, act).
   *
   * @param rvals the request needs to be mediated, usually an array
   *              of strings, can be class instances if ABAC is used.
   * @return whether to allow the request.
   */
  public async enforce(...rvals: any[]): Promise<boolean> {
    if (rvals[0] instanceof EnforceContext) {
      const enforceContext: EnforceContext = rvals.shift();
      return generatorRunAsync(this.privateEnforce(true, false, '', enforceContext, ...rvals));
    }
    return generatorRunAsync(this.privateEnforce(true, false, '', this.defaultEnforceContext, ...rvals));
  }

  /**
   * enforceWithMatcher decides whether a "subject" can access a "object" with
   * the operation "action" but with the matcher passed,
   * input parameters are usually: (matcher, sub, obj, act).
   *
   * @param matcher matcher string.
   * @param rvals the request needs to be mediated, usually an array
   *              of strings, can be class instances if ABAC is used.
   * @return whether to allow the request.
   */
  public async enforceWithMatcher(matcher: string, ...rvals: any[]): Promise<boolean> {
    if (rvals[0] instanceof EnforceContext) {
      const enforceContext: EnforceContext = rvals.shift();
      return generatorRunAsync(this.privateEnforce(true, false, matcher, enforceContext, ...rvals));
    }
    return generatorRunAsync(this.privateEnforce(true, false, matcher, this.defaultEnforceContext, ...rvals));
  }

  /**
   * enforce decides whether a "subject" can access a "object" with
   * the operation "action", input parameters are usually: (sub, obj, act).
   *
   * @param rvals the request needs to be mediated, usually an array
   *              of strings, can be class instances if ABAC is used.
   * @return whether to allow the request and the reason rule.
   */
  public async enforceEx(...rvals: any[]): Promise<[boolean, string[]]> {
    if (rvals[0] instanceof EnforceContext) {
      const enforceContext: EnforceContext = rvals.shift();
      return generatorRunAsync(this.privateEnforce(true, true, '', enforceContext, ...rvals));
    }
    return generatorRunAsync(this.privateEnforce(true, true, '', this.defaultEnforceContext, ...rvals));
  }

  /**
   * enforceExWithMatcher decides whether a "subject" can access a "object" with
   * the operation "action" but with the matcher passed,
   *  input parameters are usually: (matcher, sub, obj, act).
   *
   * @param matcher matcher string.
   * @param rvals the request needs to be mediated, usually an array
   *              of strings, can be class instances if ABAC is used.
   * @return whether to allow the request and the reason rule.
   */
  public async enforceExWithMatcher(matcher: string, ...rvals: any[]): Promise<[boolean, string[]]> {
    if (rvals[0] instanceof EnforceContext) {
      const enforceContext: EnforceContext = rvals.shift();
      return generatorRunAsync(this.privateEnforce(true, true, matcher, enforceContext, ...rvals));
    }
    return generatorRunAsync(this.privateEnforce(true, true, matcher, this.defaultEnforceContext, ...rvals));
  }

  /**
   * batchEnforce enforces each request and returns result in a bool array.
   * @param rvals the request need to be mediated, usually an array
   *              of array of strings, can be class instances if ABAC is used.
   * @returns whether to allow the requests.
   */
  public async batchEnforce(rvals: any[]): Promise<boolean[]> {
    return await Promise.all(rvals.map((rval) => this.enforce(...rval)));
  }
}
