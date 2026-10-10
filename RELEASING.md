<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Apache Casbin (Incubating) release

Commit the final version before tagging. One preparation PR contains the source, legal, dependency, packaging and workflow changes.

A `vX.Y.Z-rcN` tag exports an unsigned source candidate only, never a package registry release or GitHub latest. The release manager reviews the archive, signs it, uploads source/checksum/signature to ASF development distribution, and calls project and IPMC votes for those exact bytes. A changed candidate needs a new RC.

After approval, promote the original signed files unchanged to `https://downloads.apache.org/incubator/casbin/node-casbin-X.Y.Z-incubating/` and create the final `vX.Y.Z` tag at the same commit. Pushing the final tag alone does not publish. Run the Release workflow manually with that tag and the two public result URLs. The workflow verifies SHA-512, signature against project KEYS, and every source file/mode against Git before building package registry distributions from the approved archive. Vote-result URLs are an audit reference; the release manager is responsible for checking actual approval.

Every distribution includes LICENSE, NOTICE and DISCLAIMER. Existing GitHub assets and registry versions are never overwritten. A partial publication must be inspected by the release manager before retry; reruns fail safely when a version already exists. Signing, votes, registry credentials, channel administration and final publication are distinct later gates.
