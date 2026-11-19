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
import { ConfigInterface, newModel, newModelFromFile, newModelFromString, requiredSections, sectionNameMap } from '../../src';
import { readFileSync } from 'fs';

class MockConfig implements ConfigInterface {
  public data = new Map<string, string>();

  getBool(key: string): boolean {
    return false;
  }

  getFloat(key: string): number {
    return 0;
  }

  getInt(key: string): number {
    return 0;
  }

  getString(key: string): string {
    return this.data.get(key) || '';
  }

  getStrings(key: string): string[] {
    return [];
  }

  set(key: string, value: string): void {
    // not implementation
  }
}

const basicExample = 'examples/basic_model.conf';

const basicConfig = new MockConfig();
basicConfig.data.set('request_definition::r', 'sub, obj, act');
basicConfig.data.set('policy_definition::p', 'sub, obj, act');
basicConfig.data.set('policy_effect::e', 'some(where (p.eft == allow))');
basicConfig.data.set('matchers::m', 'r.sub == p.sub && r.obj == p.obj && r.act == p.act');

test('TestNewModel', () => {
  const m = newModel();

  expect(m !== null).toBe(true);
});

test('TestNewModelFromString', () => {
  const m = newModelFromString(readFileSync(basicExample).toString());

  expect(m !== null).toBe(true);
});

test('TestLoadModelFromConfig', (done) => {
  let m = newModel();
  m.loadModelFromConfig(basicConfig);

  m = newModel();

  try {
    m.loadModelFromConfig(new MockConfig());

    done.fail('empty config should return error');
  } catch (e) {
    if (e instanceof TypeError) {
      throw e;
    }

    if (e instanceof Error) {
      const error = e;
      requiredSections.forEach((n) => {
        if (!error.message.includes(n)) {
          throw new Error(`section name: ${sectionNameMap[n]} should be in message`);
        }
      });
    }
  }

  done();
});
