// Copyright 2026 The Casbin Authors. All Rights Reserved.
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

import { readdirSync, readFileSync } from 'fs';
import * as path from 'path';

import { newEnforcer } from '../src';

interface ConformanceTest {
  request: string[];
  allow: boolean;
  explain: string[];
}

interface ConformanceCase {
  model: string;
  policy: string;
  tests: ConformanceTest[];
}

const conformanceDir = process.env.CASBIN_CONFORMANCE_DIR;
const conformanceTest = conformanceDir ? test : test.skip;

conformanceTest('TestConformance', async () => {
  const dir = conformanceDir as string;
  const casesDir = path.join(dir, 'cases');
  const dataDir = path.join(dir, 'data');
  const files = readdirSync(casesDir)
    .filter((f) => f.endsWith('.json'))
    .sort();
  expect(files.length).toBeGreaterThan(0);

  const mismatches: string[] = [];
  for (const file of files) {
    const c: ConformanceCase = JSON.parse(readFileSync(path.join(casesDir, file), 'utf-8'));
    let e;
    try {
      e = await newEnforcer(path.join(dataDir, c.model), path.join(dataDir, c.policy));
    } catch (err) {
      mismatches.push(`${file}: newEnforcer failed: ${err}`);
      continue;
    }
    for (const t of c.tests) {
      const want = JSON.stringify([t.allow, t.explain]);
      let got: string;
      try {
        const [allow, explain] = await e.enforceEx(...t.request);
        got = JSON.stringify([allow, explain ?? []]);
      } catch (err) {
        got = `error: ${err}`;
      }
      if (got !== want) {
        mismatches.push(`${file}: request ${JSON.stringify(t.request)}: got ${got}, want ${want}`);
      }
    }
  }

  if (mismatches.length > 0) {
    throw new Error(`${mismatches.length} conformance mismatches:\n${mismatches.join('\n')}`);
  }
});
