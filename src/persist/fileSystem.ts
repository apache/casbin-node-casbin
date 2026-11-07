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
export interface FileSystem {
  readFileSync(path: string, encoding?: string): Buffer | string;
  writeFileSync(path: string, text: string, encoding?: string): void;
}

let defaultFileSystem: FileSystem | undefined = undefined;
const ErrorNoFileSystem = new Error('please set the default FileSystem by call the setDefaultFileSystem');
export const setDefaultFileSystem = (fs?: FileSystem): void => {
  defaultFileSystem = fs;
};
export const getDefaultFileSystem = (): FileSystem | undefined => defaultFileSystem;
export const mustGetDefaultFileSystem = (): FileSystem => {
  if (defaultFileSystem) {
    return defaultFileSystem;
  }
  throw ErrorNoFileSystem;
};
