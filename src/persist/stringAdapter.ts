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

import { Adapter } from './adapter';
import { Model } from '../model';
import { Helper } from './helper';

/**
 * StringAdapter is the string adapter for Casbin.
 * It can load policy from a string.
 */
export class StringAdapter implements Adapter {
  public readonly policy: string;

  /**
   * StringAdapter is the constructor for StringAdapter.
   * @param {string} policy policy formatted as a CSV string.
   */

  constructor(policy: string) {
    this.policy = policy;
  }

  public async loadPolicy(model: Model): Promise<void> {
    if (!this.policy) {
      throw new Error('Invalid policy, policy document cannot be false-y');
    }
    await this.loadRules(model, Helper.loadPolicyLine);
  }

  private async loadRules(model: Model, handler: (line: string, model: Model) => void): Promise<void> {
    const rules = this.policy.split('\n');
    rules.forEach((n: string, index: number) => {
      if (!n) {
        return;
      }
      handler(n, model);
    });
  }

  /**
   * savePolicy saves all policy rules to the storage.
   */
  public async savePolicy(model: Model): Promise<boolean> {
    throw new Error('not implemented');
  }

  /**
   * addPolicy adds a policy rule to the storage.
   */
  public async addPolicy(sec: string, ptype: string, rule: string[]): Promise<void> {
    throw new Error('not implemented');
  }

  /**
   * removePolicy removes a policy rule from the storage.
   */
  public async removePolicy(sec: string, ptype: string, rule: string[]): Promise<void> {
    throw new Error('not implemented');
  }

  /**
   * removeFilteredPolicy removes policy rules that match the filter from the storage.
   */
  public async removeFilteredPolicy(sec: string, ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<void> {
    throw new Error('not implemented');
  }
}
