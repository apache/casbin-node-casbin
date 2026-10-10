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

import { FileAdapter } from './fileAdapter';
import { BatchAdapter } from './batchAdapter';

/**
 * BatchFileAdapter is the file adapter for Casbin.
 * It can add policies and remove policies.
 * @deprecated The class should not be used, you should use FileAdapter.
 */
export class BatchFileAdapter extends FileAdapter implements BatchAdapter {
  /**
   * FileAdapter is the constructor for FileAdapter.
   * @param {string} filePath filePath the path of the policy file.
   */
  constructor(filePath: string) {
    super(filePath);
  }
}
