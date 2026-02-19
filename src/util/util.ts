// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the 'License');
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an 'AS IS' BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// escapeAssertion escapes the dots in the assertion,
// because the expression evaluation doesn't support such variable names.

import { mustGetDefaultFileSystem } from '../persist';

const escapeAssertionReg = new RegExp(/([()\s|&,=!><+\-*/]|^)((r|p)[0-9]*)\./g);

function escapeAssertion(s: string): string {
  s = s.replace(escapeAssertionReg, (match) => {
    // Replace only the last dot with underscore (preserve the prefix character)
    const lastDotIdx = match.lastIndexOf('.');
    if (lastDotIdx > 0) {
      return match.substring(0, lastDotIdx) + '_';
    }
    return match;
  });
  return s;
}

// removeComments removes the comments starting with # in the text.
function removeComments(s: string): string {
  const pos = s.indexOf('#');
  return pos > -1 ? s.slice(0, pos).trim() : s;
}

// arrayEquals determines whether two string arrays are identical.
function arrayEquals(a: string[] = [], b: string[] = []): boolean {
  const aLen = a.length;
  const bLen = b.length;
  if (aLen !== bLen) {
    return false;
  }

  for (let i = 0; i < aLen; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

// array2DEquals determines whether two 2-dimensional string arrays are identical.
function array2DEquals(a: string[][] = [], b: string[][] = []): boolean {
  const aLen = a.length;
  const bLen = a.length;
  if (aLen !== bLen) {
    return false;
  }

  for (let i = 0; i < aLen; i++) {
    if (!arrayEquals(a[i], b[i])) {
      return false;
    }
  }
  return true;
}

// arrayRemoveDuplicates removes any duplicated elements in a string array.
function arrayRemoveDuplicates(s: string[]): string[] {
  return [...new Set(s)];
}

// arrayToString gets a printable string for a string array.
function arrayToString(a: string[]): string {
  return a.join(', ');
}

// paramsToString gets a printable string for variable number of parameters.
function paramsToString(...v: string[]): string {
  return v.join(', ');
}

// setEquals determines whether two string sets are identical.
function setEquals(a: string[], b: string[]): boolean {
  return arrayEquals(a.sort(), b.sort());
}

// readFile return a promise for readFile.
function readFile(path: string, encoding?: string): Promise<string> {
  const fs = mustGetDefaultFileSystem();
  return new Promise<string>((resolve, reject) => {
    try {
      const content = fs.readFileSync(path, encoding || 'utf8') as string;
      resolve(content);
    } catch (e) {
      reject(e);
    }
  });
}

// writeFile return a promise for writeFile.
function writeFile(path: string, file: string, encoding?: string): Promise<void> {
  const fs = mustGetDefaultFileSystem();
  return new Promise<void>((resolve, reject) => {
    try {
      fs.writeFileSync(path, file, encoding || 'utf-8');
      resolve();
    } catch (e) {
      reject(e);
    }
  });
}

const evalRegG = new RegExp(/\beval\(([^),]*)\)/g);
const evalReg = new RegExp(/\beval\(([^),]*)\)/);

// hasEval determine whether matcher contains function eval
function hasEval(s: string): boolean {
  return evalReg.test(s);
}

// replaceEval replace function eval with the value of its parameters
function replaceEval(s: string, ruleName: string, rule: string): string {
  return s.replace(`eval(${ruleName})`, '(' + rule + ')');
}

// getEvalValue returns the parameters of function eval
function getEvalValue(s: string): string[] {
  const subMatch = s.match(evalRegG);
  const rules: string[] = [];
  if (!subMatch) {
    return [];
  }
  for (const rule of subMatch) {
    const index: number = rule.indexOf('(');
    rules.push(rule.slice(index + 1, -1));
  }
  return rules;
}

// generatorRunSync handle generator function in Sync model and return value which is not Promise
function generatorRunSync(iterator: Generator<any>): any {
  let { value, done } = iterator.next();
  while (true) {
    if (value instanceof Promise) {
      throw new Error('cannot handle Promise in generatorRunSync, Please use generatorRunAsync');
    }
    if (!done) {
      const temp = value;
      ({ value, done } = iterator.next(temp));
    } else {
      return value;
    }
  }
}

// generatorRunAsync handle generator function in Async model and return Promise
async function generatorRunAsync(iterator: Generator<any>): Promise<any> {
  let { value, done } = iterator.next();
  while (true) {
    if (!done) {
      const temp = await value;
      ({ value, done } = iterator.next(temp));
    } else {
      return value;
    }
  }
}

function deepCopy(obj: Array<any> | any): any {
  if (typeof obj !== 'object') return;
  const newObj: any = obj instanceof Array ? [] : {};
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      newObj[key] = typeof obj[key] === 'object' ? deepCopy(obj[key]) : obj[key];
    }
  }
  return newObj;
}

function customIn(a: number | string, b: number | string): number {
  if ((b as any) instanceof Array) {
    return (((b as any) as Array<any>).includes(a) as unknown) as number;
  }
  return ((a in (b as any)) as unknown) as number;
}

function bracketCompatible(exp: string): string {
  // TODO: This function didn't support nested bracket.
  if (!(exp.includes(' in ') && exp.includes(' ('))) {
    return exp;
  }

  const re = / \([^)]*\)/g;
  const array = exp.split('');

  let reResult: RegExpExecArray | null;
  while ((reResult = re.exec(exp)) !== null) {
    if (!(reResult[0] as string).includes(',')) {
      continue;
    }
    array[reResult.index + 1] = '[';
    array[re.lastIndex - 1] = ']';
  }
  exp = array.join('');
  return exp;
}

export {
  escapeAssertion,
  removeComments,
  arrayEquals,
  array2DEquals,
  arrayRemoveDuplicates,
  arrayToString,
  paramsToString,
  setEquals,
  readFile,
  writeFile,
  hasEval,
  replaceEval,
  getEvalValue,
  generatorRunSync,
  generatorRunAsync,
  deepCopy,
  customIn,
  bracketCompatible,
};
