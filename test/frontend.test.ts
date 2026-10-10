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

import { readFileSync } from 'fs';
import { newEnforcer } from '../src';
import { casbinJsGetPermissionForUser } from '../src';

test('TestCasbinJsGetPermissionForUser', async () => {
  const e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_with_hierarchy_policy.csv');
  const a = await casbinJsGetPermissionForUser(e, 'alice');
  const b = await casbinJsGetPermissionForUser(e, 'alice');
  if (a !== b) {
    throw new Error('Unexpected side affect.');
  }
  const received = JSON.parse(await casbinJsGetPermissionForUser(e, 'alice'));
  let expectedModelStr = readFileSync('examples/rbac_model.conf').toString();

  // avoid the impact of line breaks changing to CRLF, when automatic conversion is enabled
  expectedModelStr = expectedModelStr.replace(/\r\n/g, '\n');
  // Model serialization omits comments, including the fixture's license header.
  expectedModelStr = expectedModelStr.replace(/^#.*\n/gm, '').trimStart();

  expect(received['m']).toBe(expectedModelStr.replace(/\n\n/g, '\n'));
  const expectedPoliciesStr = readFileSync('examples/rbac_with_hierarchy_policy.csv').toString();

  let expectedPolicyItem = expectedPoliciesStr.split(RegExp(',|\n'));
  expectedPolicyItem = expectedPolicyItem.filter((item) => item !== null && item.trim() !== '');

  let i = 0;
  for (const sArr of received['p']) {
    for (const s of sArr) {
      expect(s.trim()).toEqual(expectedPolicyItem[i].trim());
      i = i + 1;
    }
  }
});
