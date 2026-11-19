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

export class EnforceContext {
  public pType: string;
  public rType: string;
  public eType: string;
  public mType: string;

  constructor(rType: string, pType: string, eType: string, mType: string) {
    this.pType = pType;
    this.eType = eType;
    this.mType = mType;
    this.rType = rType;
  }
}

export const newEnforceContext = (index: string): EnforceContext => {
  return new EnforceContext('r' + index, 'p' + index, 'e' + index, 'm' + index);
};
