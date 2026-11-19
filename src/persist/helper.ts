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
import { Model } from '../model';
import { parse } from 'csv-parse/sync';

export interface IPolicyParser {
  parse(line: string): string[][] | null;
}

export class BasicCsvParser implements IPolicyParser {
  parse(line: string): string[][] | null {
    if (!line || line.trimStart().charAt(0) === '#') {
      return null;
    }

    return parse(line, {
      delimiter: ',',
      skip_empty_lines: true,
      trim: true,
      relax_quotes: true,
    });
  }
}

export class BracketAwareCsvParser implements IPolicyParser {
  private readonly baseParser: IPolicyParser;

  constructor(baseParser: IPolicyParser = new BasicCsvParser()) {
    this.baseParser = baseParser;
  }

  parse(line: string): string[][] | null {
    const rawTokens = this.baseParser.parse(line);
    if (!rawTokens || !rawTokens[0]) {
      return null;
    }

    const tokens = rawTokens[0];
    const processedTokens: string[] = [];
    let currentToken = '';
    let bracketCount = 0;

    for (const token of tokens) {
      for (const char of token) {
        if (char === '(') bracketCount++;
        else if (char === ')') bracketCount--;
      }

      currentToken += (currentToken ? ',' : '') + token;

      if (bracketCount === 0) {
        processedTokens.push(currentToken);
        currentToken = '';
      }
    }

    if (bracketCount !== 0) {
      throw new Error(`Unmatched brackets in policy line: ${line}`);
    }

    return processedTokens.length > 0 ? [processedTokens] : null;
  }
}

export class PolicyLoader {
  private readonly parser: IPolicyParser;

  constructor(parser: IPolicyParser = new BracketAwareCsvParser()) {
    this.parser = parser;
  }

  loadPolicyLine(line: string, model: Model): void {
    const tokens = this.parser.parse(line);
    if (!tokens || !tokens[0]) {
      return;
    }

    let key = tokens[0][0].trim();
    if (key.startsWith('"') && key.endsWith('"')) {
      key = key.slice(1, -1);
    }

    const sec = key.substring(0, 1);
    const item = model.model.get(sec);
    if (!item) {
      return;
    }

    const policy = item.get(key);
    if (!policy) {
      return;
    }

    const values = tokens[0].slice(1).map((v) => {
      if (v.startsWith('"') && v.endsWith('"')) {
        v = v.slice(1, -1);
      }
      return v.replace(/""/g, '"').trim();
    });

    policy.policy.push(values);
  }
}

export class Helper {
  private static readonly policyLoader = new PolicyLoader();

  public static loadPolicyLine(line: string, model: Model): void {
    Helper.policyLoader.loadPolicyLine(line, model);
  }
}
