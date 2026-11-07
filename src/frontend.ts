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

import { Enforcer } from './enforcer';
import { deepCopy } from './util';

/**
 * Experiment!
 * getPermissionForCasbinJs returns a string include the whole model.
 * You can pass the returned string to the frontend and manage your webpage widgets and APIs with Casbin.js.
 * @param e the initialized enforcer
 * @param user the user
 */
export async function casbinJsGetPermissionForUser(e: Enforcer, user?: string): Promise<string> {
  const obj: any = {};

  const m = e.getModel().model;
  let s = '';
  s += '[request_definition]\n';
  s += `r = ${m.get('r')?.get('r')?.value.replace(/_/g, '.')}\n`;
  s += '[policy_definition]\n';
  s += `p = ${m.get('p')?.get('p')?.value.replace(/_/g, '.')}\n`;
  if (m.get('g')?.get('g') !== undefined) {
    s += '[role_definition]\n';
    s += `g = ${m.get('g')?.get('g')?.value}\n`;
  }
  s += '[policy_effect]\n';
  s += `e = ${m.get('e')?.get('e')?.value.replace(/_/g, '.')}\n`;
  s += '[matchers]\n';
  s += `m = ${m.get('m')?.get('m')?.value.replace(/_/g, '.')}`;
  obj['m'] = s;

  const policy = deepCopy(await e.getPolicy());
  const groupPolicy = deepCopy(await e.getGroupingPolicy());

  policy.forEach((item: string[]) => {
    item.unshift('p');
  });

  groupPolicy.forEach((item: string[]) => {
    item.unshift('g');
  });

  obj['p'] = [...policy, ...groupPolicy];

  return JSON.stringify(obj);
}
