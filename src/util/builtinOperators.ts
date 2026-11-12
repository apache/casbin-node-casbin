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

import * as rbac from '../rbac';
import { ip } from './ip';

// regexMatch determines whether key1 matches the pattern of key2 in regular expression.
function regexMatch(key1: string, key2: string): boolean {
  return new RegExp(key2).test(key1);
}

// keyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path),
// key2 can contain a *.
// For example, '/foo/bar' matches '/foo/*'
function keyMatch(key1: string, key2: string): boolean {
  const pos: number = key2.indexOf('*');
  if (pos === -1) {
    return key1 === key2;
  }

  if (key1.length > pos) {
    return key1.slice(0, pos) === key2.slice(0, pos);
  }

  return key1 === key2.slice(0, pos);
}

// keyMatchFunc is the wrapper for keyMatch.
function keyMatchFunc(...args: any[]): boolean {
  const [arg0, arg1] = args;
  const name1: string = (arg0 || '').toString();
  const name2: string = (arg1 || '').toString();

  return keyMatch(name1, name2);
}

// KeyGet returns the matched part
// For example, "/foo/bar/foo" matches "/foo/*"
// "bar/foo" will been returned
function keyGet(key1: string, key2: string): string {
  const pos: number = key2.indexOf('*');
  if (pos === -1) {
    return '';
  }
  if (key1.length > pos) {
    if (key1.slice(0, pos) === key2.slice(0, pos)) {
      return key1.slice(pos, key1.length);
    }
  }
  return '';
}

// keyGetFunc is the wrapper for keyGet.
function keyGetFunc(...args: any[]): string {
  const [arg0, arg1] = args;
  const name1: string = (arg0 || '').toString();
  const name2: string = (arg1 || '').toString();

  return keyGet(name1, name2);
}

// keyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path),
// key2 can contain a *.
// For example, '/foo/bar' matches '/foo/*', '/resource1' matches '/:resource'
function keyMatch2(key1: string, key2: string): boolean {
  key2 = key2.replace(/\/\*/g, '/.*');

  const regexp = new RegExp(/(.*):[^/]+(.*)/g);
  for (;;) {
    if (!key2.includes('/:')) {
      break;
    }
    const replaced = key2.replace(regexp, '$1[^/]+$2');
    if (replaced === key2) {
      break;
    }
    key2 = replaced;
  }

  if (key2 === '*') {
    key2 = '(.*)';
  }
  return regexMatch(key1, '^' + key2 + '$');
}

// keyMatch2Func is the wrapper for keyMatch2.
function keyMatch2Func(...args: any[]): boolean {
  const [arg0, arg1] = args;
  const name1: string = (arg0 || '').toString();
  const name2: string = (arg1 || '').toString();

  return keyMatch2(name1, name2);
}

// KeyGet2 returns value matched pattern
// For example, "/resource1" matches "/:resource"
// if the pathVar == "resource", then "resource1" will be returned
function keyGet2(key1: string, key2: string, pathVar: string): string {
  if (keyMatch2(key1, key2)) {
    const re = new RegExp('[^/]+', 'g');
    const keys = key2.match(re);
    const values = key1.match(re);
    if (!keys || !values) {
      return '';
    }
    const index = keys.indexOf(`:${pathVar}`);
    if (index === -1) {
      return '';
    }
    return values[index];
  } else {
    return '';
  }
}

function keyGet2Func(...args: any[]): string {
  const [arg0, arg1, arg2] = args;
  const name1: string = (arg0 || '').toString();
  const name2: string = (arg1 || '').toString();
  const name3: string = (arg2 || '').toString();

  return keyGet2(name1, name2, name3);
}

// keyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, '/foo/bar' matches '/foo/*', '/resource1' matches '/{resource}'
function keyMatch3(key1: string, key2: string): boolean {
  key2 = key2.replace(/\/\*/g, '/.*');

  const regexp = new RegExp(/(.*){[^/]+}(.*)/g);
  for (;;) {
    if (!key2.includes('/{')) {
      break;
    }
    const replaced = key2.replace(regexp, '$1[^/]+$2');
    if (replaced === key2) {
      break;
    }
    key2 = replaced;
  }

  return regexMatch(key1, '^' + key2 + '$');
}

// keyMatch3Func is the wrapper for keyMatch3.
function keyMatch3Func(...args: any[]): boolean {
  const [arg0, arg1] = args;
  const name1: string = (arg0 || '').toString();
  const name2: string = (arg1 || '').toString();

  return keyMatch3(name1, name2);
}

// keyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// Besides what keyMatch3 does, keyMatch4 can also match repeated patterns:
// "/parent/123/child/123" matches "/parent/{id}/child/{id}"
// "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
// But keyMatch3 will match both.
function keyMatch4(key1: string, key2: string): boolean {
  key2 = key2.replace(/\/\*/g, '/.*');

  const tokens: string[] = [];
  let j = -1;
  for (let i = 0; i < key2.length; i++) {
    const c = key2.charAt(i);
    if (c === '{') {
      j = i;
    } else if (c === '}') {
      tokens.push(key2.substring(j, i + 1));
    }
  }

  let regexp = new RegExp(/(.*){[^/]+}(.*)/g);

  for (;;) {
    if (!key2.includes('/{')) {
      break;
    }
    const replaced = key2.replace(regexp, '$1([^/]+)$2');
    if (replaced === key2) {
      break;
    }
    key2 = replaced;
  }

  regexp = new RegExp('^' + key2 + '$');

  let values: RegExpExecArray | null | string[] = regexp.exec(key1);

  if (!values) {
    return false;
  }

  values = values.slice(1);

  if (tokens.length !== values.length) {
    throw new Error('KeyMatch4: number of tokens is not equal to number of values');
  }

  const m = new Map<string, string[]>();
  tokens.forEach((n, index) => {
    const key = tokens[index];
    let v = m.get(key);
    if (!v) {
      v = [];
    }

    if (values) {
      v.push(values[index]);
    }
    m.set(key, v);
  });

  for (const value of m.values()) {
    for (let i = 1; i < value.length; i++) {
      if (value[i] !== value[0]) {
        return false;
      }
    }
  }

  return true;
}

// keyMatch4Func is the wrapper for keyMatch4.
function keyMatch4Func(...args: any[]): boolean {
  const [arg0, arg1] = args;
  const name1: string = (arg0 || '').toString();
  const name2: string = (arg1 || '').toString();

  return keyMatch4(name1, name2);
}

// KeyMatch determines whether key1 matches the pattern of key2 and ignores the parameters in key2.
// For example, "/foo/bar?status=1&type=2" matches "/foo/bar"
function KeyMatch5(key1: string, key2: string): boolean {
  const i: number = key1.indexOf('?');
  if (i !== -1) {
    key1 = key1.slice(0, i);
  }

  key2 = key2.replace(/\/\*/g, '/.*');

  const regexp = new RegExp(/(.*){[^/]+}(.*)/g);
  for (;;) {
    if (!key2.includes('/{')) {
      break;
    }
    const replaced = key2.replace(regexp, '$1[^/]+$2');
    if (replaced === key2) {
      break;
    }
    key2 = replaced;
  }

  return regexMatch(key1, '^' + key2 + '$');
}

// keyMatch5Func is the wrapper for KeyMatch5.
function keyMatch5Func(...args: any[]): boolean {
  const [arg0, arg1] = args;
  const name1: string = (arg0 || '').toString();
  const name2: string = (arg1 || '').toString();

  return KeyMatch5(name1, name2);
}

// regexMatchFunc is the wrapper for regexMatch.
function regexMatchFunc(...args: any[]): boolean {
  const [arg0, arg1] = args;
  const name1: string = (arg0 || '').toString();
  const name2: string = (arg1 || '').toString();

  return regexMatch(name1, name2);
}

// ipMatch determines whether IP address ip1 matches the pattern of IP address ip2,
// ip2 can be an IP address or a CIDR pattern.
// For example, '192.168.2.123' matches '192.168.2.0/24'
function ipMatch(ip1: string, ip2: string): boolean {
  // check ip1
  if (!(ip.isV4Format(ip1) || ip.isV6Format(ip1))) {
    throw new Error('invalid argument: ip1 in ipMatch() function is not an IP address.');
  }
  // check ip2
  const cidrParts: string[] = ip2.split('/');
  if (cidrParts.length === 2) {
    return ip.cidrSubnet(ip2).contains(ip1);
  } else {
    if (!(ip.isV4Format(ip2) || ip.isV6Format(ip2))) {
      throw new Error('invalid argument: ip2 in ipMatch() function is not an IP address.');
    }
    return ip.isEqual(ip1, ip2);
  }
}

// ipMatchFunc is the wrapper for ipMatch.
function ipMatchFunc(...args: any[]): boolean {
  const [arg0, arg1] = args;
  const ip1: string = (arg0 || '').toString();
  const ip2: string = (arg1 || '').toString();

  return ipMatch(ip1, ip2);
}

// Glob matching with the same rules as Go Casbin's util.GlobMatch
// (github.com/bmatcuk/doublestar/v4): `*` matches any run of non-`/`
// characters (also empty and dot-files), `?` one non-`/` character, `**` as
// a whole path segment zero or more directories, `[...]` / `[!...]` /
// `[^...]` a character class, `{a,b}` alternatives and `\` escapes the next
// character. A leading `!` is a literal character, not a negation.
//
// Matching is a dynamic program over (token, position), so it takes
// O(tokens * length) time and never backtracks.

type GlobToken =
  | { t: 'lit'; c: string }
  | { t: 'one' }
  | { t: 'cls'; neg: boolean; ranges: [string, string][] }
  | { t: 'star' } // `*`: any run of non-`/` characters
  | { t: 'dirs' } // `**/`: zero or more directories
  | { t: 'any' } // `**` as the whole pattern: anything
  | { t: 'tailAny' } // trailing `/**`: nothing, or `/` and anything
  | { t: 'tailDirs' }; // trailing `/**/`: nothing, or `/` and directories

const maxGlobAlternatives = 1024;

// globExpandBraces expands `{a,b}` into separate patterns.
// Returns null for an unclosed `{` or too many alternatives.
function globExpandBraces(pattern: string): string[] | null {
  let open = -1;
  let depth = 0;
  const commas: number[] = [];
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '\\') {
      i++;
    } else if (c === '[') {
      const close = pattern.indexOf(']', i + 2);
      if (close !== -1) {
        i = close;
      }
    } else if (c === '{') {
      if (depth === 0) {
        open = i;
      }
      depth++;
    } else if (c === ',' && depth === 1) {
      commas.push(i);
    } else if (c === '}' && depth > 0) {
      depth--;
      if (depth === 0) {
        const prefix = pattern.slice(0, open);
        const suffix = pattern.slice(i + 1);
        const bounds = [open, ...commas, i];
        const out: string[] = [];
        for (let k = 0; k + 1 < bounds.length; k++) {
          const expanded = globExpandBraces(prefix + pattern.slice(bounds[k] + 1, bounds[k + 1]) + suffix);
          if (expanded === null || out.length + expanded.length > maxGlobAlternatives) {
            return null;
          }
          out.push(...expanded);
        }
        return out;
      }
    }
  }
  return depth > 0 ? null : [pattern];
}

// globTokenize turns a pattern without braces into tokens.
// Returns null for a bad pattern.
function globTokenize(pattern: string): GlobToken[] | null {
  const tokens: GlobToken[] = [];
  const last = (): GlobToken | undefined => tokens[tokens.length - 1];
  const afterSlash = (): boolean => {
    const l = last();
    return l !== undefined && l.t === 'lit' && l.c === '/';
  };
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '\\') {
      i++;
      if (i === pattern.length) {
        return null;
      }
      tokens.push({ t: 'lit', c: pattern[i] });
    } else if (c === '*') {
      let j = i;
      while (pattern[j + 1] === '*') {
        j++;
      }
      const segmentStart = i === 0 || pattern[i - 1] === '/';
      const segmentEnd = j + 1 === pattern.length || pattern[j + 1] === '/';
      if (j > i && segmentStart && segmentEnd) {
        if (j + 2 < pattern.length || (j + 2 === pattern.length && !afterSlash())) {
          // Repeated `**/` mean the same as one.
          if (last()?.t !== 'dirs') {
            tokens.push({ t: 'dirs' });
          }
          j++;
        } else if (j + 2 === pattern.length) {
          // A trailing `/**/` also matches the parent without the slash.
          tokens.pop();
          tokens.push({ t: 'tailDirs' });
          j++;
        } else if (afterSlash()) {
          // A trailing `/**` also matches the parent itself.
          tokens.pop();
          tokens.push({ t: 'tailAny' });
        } else if (last()?.t === 'dirs') {
          tokens[tokens.length - 1] = { t: 'any' };
        } else {
          tokens.push({ t: 'any' });
        }
      } else {
        tokens.push({ t: 'star' });
      }
      i = j;
    } else if (c === '?') {
      tokens.push({ t: 'one' });
    } else if (c === '[') {
      let j = i + 1;
      const neg = pattern[j] === '!' || pattern[j] === '^';
      if (neg) {
        j++;
      }
      const chars: string[] = [];
      const ranges: [string, string][] = [];
      for (; j < pattern.length && pattern[j] !== ']'; j++) {
        if (pattern[j] === '\\') {
          j++;
          if (j === pattern.length) {
            return null;
          }
        }
        chars.push(pattern[j]);
      }
      if (j === pattern.length || chars.length === 0) {
        return null;
      }
      for (let k = 0; k < chars.length; k++) {
        if (chars[k + 1] === '-' && k + 2 < chars.length) {
          if (chars[k] > chars[k + 2]) {
            return null;
          }
          ranges.push([chars[k], chars[k + 2]]);
          k += 2;
        } else {
          ranges.push([chars[k], chars[k]]);
        }
      }
      tokens.push({ t: 'cls', neg, ranges });
      i = j;
    } else {
      tokens.push({ t: 'lit', c });
    }
  }
  return tokens;
}

function globMatchTokens(tokens: GlobToken[], s: string): boolean {
  const n = s.length;
  // next[k]: tokens after the current one match s.slice(k).
  let next = new Uint8Array(n + 1);
  next[n] = 1;
  for (let t = tokens.length - 1; t >= 0; t--) {
    const tok = tokens[t];
    const cur = new Uint8Array(n + 1);
    let run = 0; // for `dirs`: s.slice(k) is a non-`/` run, `/`, then a match
    for (let k = n; k >= 0; k--) {
      const c = s[k];
      let ok = false;
      switch (tok.t) {
        case 'lit':
          ok = k < n && c === tok.c && next[k + 1] === 1;
          break;
        case 'one':
          ok = k < n && c !== '/' && next[k + 1] === 1;
          break;
        case 'cls': {
          if (k < n && next[k + 1] === 1) {
            const inClass = tok.ranges.some(([lo, hi]) => c >= lo && c <= hi);
            ok = inClass !== tok.neg;
          }
          break;
        }
        case 'star':
          ok = next[k] === 1 || (k < n && c !== '/' && cur[k + 1] === 1);
          break;
        case 'any':
          ok = next[k] === 1 || (k < n && cur[k + 1] === 1);
          break;
        case 'dirs':
          if (k < n) {
            run = c === '/' ? cur[k + 1] : run;
          }
          ok = next[k] === 1 || (k < n && run === 1);
          break;
        case 'tailAny':
          ok = k === n || c === '/';
          break;
        case 'tailDirs':
          ok = k === n || (c === '/' && (k + 1 === n || s[n - 1] === '/'));
          break;
      }
      cur[k] = ok ? 1 : 0;
    }
    next = cur;
  }
  return next[0] === 1;
}

/**
 * Returns true if the specified `string` matches the given glob `pattern`.
 * Same rules as Go Casbin's util.GlobMatch, see globTokenize.
 *
 * @param string String to match
 * @param pattern Glob pattern to use for matching.
 * @returns Returns true if the string matches the glob pattern.
 *
 * @example
 * ```javascript
 * globMatch("abc.conf", "*.conf") => true
 * ```
 */
function globMatch(string: string, pattern: string): boolean {
  const patterns = globExpandBraces(pattern);
  if (patterns === null) {
    return false;
  }
  for (const p of patterns) {
    const tokens = globTokenize(p);
    if (tokens === null) {
      return false;
    }
    if (globMatchTokens(tokens, string)) {
      return true;
    }
  }
  return false;
}

// generateGFunction is the factory method of the g(_, _) function.
function generateGFunction(rm: rbac.RoleManager): any {
  const memorized = new Map<string, boolean>();
  return async function (...args: any[]): Promise<boolean> {
    const key = args.toString();
    let value = memorized.get(key);
    if (value) {
      return value;
    }

    const [arg0, arg1] = args;
    const name1: string = (arg0 || '').toString();
    const name2: string = (arg1 || '').toString();

    if (!rm) {
      value = name1 === name2;
    } else if (args.length === 2) {
      value = await rm.hasLink(name1, name2);
    } else {
      const domain: string = args[2].toString();
      value = await rm.hasLink(name1, name2, domain);
    }

    memorized.set(key, value);
    return value;
  };
}

// generateSyncedGFunction is the synchronous factory method of the g(_, _) function.
function generateSyncedGFunction(rm: rbac.RoleManager): any {
  const memorized = new Map<string, boolean>();
  return function (...args: any[]): boolean {
    const key = args.toString();
    let value = memorized.get(key);
    if (value) {
      return value;
    }

    const [arg0, arg1] = args;
    const name1: string = (arg0 || '').toString();
    const name2: string = (arg1 || '').toString();

    if (!rm) {
      value = name1 === name2;
    } else if (!rm?.syncedHasLink) {
      throw new Error('RoleManager requires syncedHasLink for synchronous execution');
    } else if (args.length === 2) {
      value = rm.syncedHasLink(name1, name2);
    } else {
      const domain: string = args[2].toString();
      value = rm.syncedHasLink(name1, name2, domain);
    }

    memorized.set(key, value);
    return value;
  };
}

export {
  keyMatchFunc,
  keyGetFunc,
  keyMatch2Func,
  keyGet2Func,
  keyMatch3Func,
  regexMatchFunc,
  ipMatchFunc,
  generateSyncedGFunction,
  generateGFunction,
  keyMatch4Func,
  keyMatch5Func,
  globMatch,
};
