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

import { newEnforcer, newEnforceContext } from '../src';

test('TestMultiplePolicyDefinitions', async () => {
  const e = await newEnforcer('examples/multiple_policy_definitions_model.conf', 'examples/multiple_policy_definitions_policy.csv');
  const enforceContext = newEnforceContext('2');
  enforceContext.eType = 'e';

  // Test with default context (r, p, e, m)
  await expect(e.enforce('alice', 'data2', 'read')).resolves.toBe(true);

  // Test with EnforceContext for r2, p2, e, m2
  await expect(e.enforce(enforceContext, { Age: 70 }, '/data1', 'read')).resolves.toBe(false);
  await expect(e.enforce(enforceContext, { Age: 30 }, '/data1', 'read')).resolves.toBe(true);
});
