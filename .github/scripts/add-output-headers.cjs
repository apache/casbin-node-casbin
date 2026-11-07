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


const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
function header(source) {
  const text = fs.readFileSync(path.join(root, source), 'utf8').replace(/\r\n/g, '\n');
  const match = text.match(/^(?:\/\/[^\n]*\n)+/);
  if (!match || !match[0].includes('License')) throw new Error(`Missing source license: ${source}`);
  return match[0].trimEnd() + '\n\n';
}
function prepend(file, banner) {
  const text = fs.readFileSync(file, 'utf8');
  if (!text.startsWith(banner)) fs.writeFileSync(file, banner + text);
}
function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(file);
    else if (/\.(?:js|d\.ts)$/.test(entry.name)) {
      const relative = path.relative(path.join(root, 'lib/cjs'), file).replace(/\.(?:d\.ts|js)$/, '.ts');
      prepend(file, header(path.join('src', relative)));
    }
  }
}
walk(path.join(root, 'lib/cjs'));
// The ESM bundle includes both contributed code and the adapted MIT node-ip subset.
prepend(path.join(root, 'lib/esm/index.mjs'), header('src/index.ts') + header('src/util/ip.ts'));
