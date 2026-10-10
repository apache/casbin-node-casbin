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

import { FilteredAdapter } from './filteredAdapter';
import { Model } from '../model';
import { FileAdapter } from './fileAdapter';
import { Helper } from './helper';
import { readFile } from '../util';

export class Filter {
  public g: string[] = [];
  public p: string[] = [];
}

export class DefaultFilteredAdapter extends FileAdapter implements FilteredAdapter {
  private filtered: boolean;

  constructor(filePath: string) {
    super(filePath);
    this.filtered = false;
  }

  // loadPolicy loads all policy rules from the storage.
  public async loadPolicy(model: Model): Promise<void> {
    this.filtered = false;
    await super.loadPolicy(model);
  }

  public async loadFilteredPolicy(model: Model, filter: Filter): Promise<void> {
    if (!filter) {
      await this.loadPolicy(model);
      return;
    }

    if (!this.filePath) {
      throw new Error('invalid file path, file path cannot be empty');
    }

    await this.loadFilteredPolicyFile(model, filter, Helper.loadPolicyLine);
    this.filtered = true;
  }

  private async loadFilteredPolicyFile(model: Model, filter: Filter, handler: (line: string, model: Model) => void): Promise<void> {
    const bodyBuf = await readFile(this.filePath);
    const lines = bodyBuf.toString().split('\n');
    lines.forEach((n: string, index: number) => {
      const line = n;
      if (!line || DefaultFilteredAdapter.filterLine(line, filter)) {
        return;
      }
      handler(line, model);
    });
  }

  public isFiltered(): boolean {
    return this.filtered;
  }

  public async savePolicy(model: Model): Promise<boolean> {
    if (this.filtered) {
      throw new Error('cannot save a filtered policy');
    }
    return super.savePolicy(model);
  }

  private static filterLine(line: string, filter: Filter): boolean {
    if (!filter) {
      return false;
    }
    const p = line.split(',');
    if (p.length === 0) {
      return true;
    }
    let filterSlice: string[] = [];
    switch (p[0].trim()) {
      case 'p':
        filterSlice = filter.p;
        break;
      case 'g':
        filterSlice = filter.g;
        break;
    }

    return DefaultFilteredAdapter.filterWords(p, filterSlice);
  }

  private static filterWords(line: string[], filter: string[]): boolean {
    if (line.length < filter.length + 1) {
      return true;
    }
    let skipLine = false;
    for (let i = 0; i < filter.length; i++) {
      if (filter[i] && filter[i] !== filter[i + 1]) {
        skipLine = true;
        break;
      }
    }
    return skipLine;
  }
}
