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

import { Config } from '../../src';
import { readFileSync } from 'fs';

const config = Config.newConfigFromText(readFileSync('test/config/testini.ini').toString());

describe('multi-line test', () => {
  it('should config.get("multi1::name") to equal r.sub==p.sub&&r.obj==p.obj', function () {
    expect(config.get('multi1::name')).toEqual('r.sub==p.sub&&r.obj==p.obj');
  });

  it('should config.get("multi2::name") to equal r.sub==p.sub&&r.obj==p.obj', function () {
    expect(config.get('multi2::name')).toEqual('r.sub==p.sub&&r.obj==p.obj');
  });

  it('should config.get("multi3::name") to equal r.sub==p.sub&&r.obj==p.obj', function () {
    expect(config.get('multi3::name')).toEqual('r.sub==p.sub&&r.obj==p.obj');
  });

  it('should config.get("multi4::name") to equal r.sub==p.sub&&r.obj==p.obj', function () {
    expect(config.get('multi4::name')).toEqual('');
  });

  it('should config.get("multi5::name") to equal r.sub==p.sub&&r.obj==p.obj', function () {
    expect(config.get('multi5::name')).toEqual('r.sub==p.sub&&r.obj==p.obj');
  });

  it('should config.get("multi6::name") to equal r.sub==p.sub&&r.obj==p.obj&&r.tex==p.tex', function () {
    expect(config.get('multi6::name')).toEqual('r.sub==p.sub&&r.obj==p.obj&&r.tex==p.tex');
  });

  it('should config.get("mysql::mysql.master.host") to equal 10.0.0.1', function () {
    expect(config.get('mysql::mysql.master.host')).toEqual('10.0.0.1');
  });
  it('should config.get("mysql::mysql.master.user") to equal root', function () {
    expect(config.get('mysql::mysql.master.user')).toEqual('root');
  });
});
