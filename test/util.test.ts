// Copyright 2018 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { getLogger, logPrint, Util as util } from '../src';
import { ip } from '../src/util/ip';
import { compile } from '@casbin/expression-eval';

test('test enableLog success', () => {
  getLogger().enableLog(true);
  expect(getLogger().isEnable()).toEqual(true);
  getLogger().enableLog(false);
  expect(getLogger().isEnable()).toEqual(false);
});

test('test enableLog failed', () => {
  getLogger().enableLog(true);
  expect(getLogger().isEnable()).not.toEqual(false);
  getLogger().enableLog(false);
  expect(getLogger().isEnable()).not.toEqual(true);
});

test('test logPrint', () => {
  getLogger().enableLog(true);
  expect(logPrint('test log')).toBeUndefined();
});

test('test Valuate', () => {
  expect(compile('1 + 1 === 2')({})).toEqual(true);
  expect(compile('1 + 1 !== 2')({})).toEqual(false);
});

test('test regexMatchFunc', () => {
  expect(util.regexMatchFunc('foobar', '^foo*')).toEqual(true);
  expect(util.regexMatchFunc('barfoo', '^foo*')).toEqual(false);
});

test('test keyMatchFunc', () => {
  expect(util.keyMatchFunc('/foo/bar', '/foo/*')).toEqual(true);
  expect(util.keyMatchFunc('/bar/foo', '/foo/*')).toEqual(false);
});

test('test keyGetFunc', () => {
  expect(util.keyGetFunc('/foo/bar', '/foo/*')).toEqual('bar');
  expect(util.keyGetFunc('/bar/foo', '/foo/*')).toEqual('');
});

test('test keyMatch2Func', () => {
  expect(util.keyMatch2Func('/foo/bar', '/foo/*')).toEqual(true);
  expect(util.keyMatch2Func('/foo/baz', '/foo/:bar')).toEqual(true);
  expect(util.keyMatch2Func('/foo/baz/foo', '/foo/:bar/foo')).toEqual(true);
  expect(util.keyMatch2Func('/baz', '/foo')).toEqual(false);
  expect(util.keyMatch2Func('/foo/baz', '/foo')).toEqual(false);
});

test('test keyGet2Func', () => {
  expect(util.keyGet2Func('/foo/bar', '/foo/*', 'bar')).toEqual('');
  expect(util.keyGet2Func('/foo/baz', '/foo/:bar', 'bar')).toEqual('baz');
  expect(util.keyGet2Func('/foo/baz/foo', '/foo/:bar/foo', 'bar')).toEqual('baz');
  expect(util.keyGet2Func('/baz', '/foo', 'bar')).toEqual('');
  expect(util.keyGet2Func('/foo/baz', '/foo', 'bar')).toEqual('');
});

test('test keyMatch3Func', () => {
  expect(util.keyMatch3Func('/foo/bar', '/foo/*')).toEqual(true);
  expect(util.keyMatch3Func('/foo/baz', '/foo/{bar}')).toEqual(true);
  expect(util.keyMatch3Func('/foo/baz/foo', '/foo/{bar}/foo')).toEqual(true);
  expect(util.keyMatch3Func('/baz', '/foo')).toEqual(false);
  expect(util.keyMatch3Func('/foo/baz', '/foo')).toEqual(false);
});

test('test keyMatch4Func', () => {
  expect(util.keyMatch4Func('/parent/123/child/123', '/parent/{id}/child/{id}')).toEqual(true);
  expect(util.keyMatch4Func('/parent/123/child/456', '/parent/{id}/child/{id}')).toEqual(false);

  expect(util.keyMatch4Func('/parent/123/child/123', '/parent/{id}/child/{another_id}')).toEqual(true);
  expect(util.keyMatch4Func('/parent/123/child/456', '/parent/{id}/child/{another_id}')).toEqual(true);

  expect(util.keyMatch4Func('/parent/123/child/123/book/123', '/parent/{id}/child/{id}/book/{id}')).toEqual(true);
  expect(util.keyMatch4Func('/parent/123/child/123/book/456', '/parent/{id}/child/{id}/book/{id}')).toEqual(false);
  expect(util.keyMatch4Func('/parent/123/child/456/book/123', '/parent/{id}/child/{id}/book/{id}')).toEqual(false);
  expect(util.keyMatch4Func('/parent/123/child/456/book/', '/parent/{id}/child/{id}/book/{id}')).toEqual(false);
  expect(util.keyMatch4Func('/parent/123/child/456', '/parent/{id}/child/{id}/book/{id}')).toEqual(false);
});

test('test keyMatch5Func', () => {
  expect(util.keyMatch5Func('/parent/child?status=1&type=2', '/parent/child')).toEqual(true);
  expect(util.keyMatch5Func('/parent?status=1&type=2', '/parent/child')).toEqual(false);

  expect(util.keyMatch5Func('/parent/child/?status=1&type=2', '/parent/child/')).toEqual(true);
  expect(util.keyMatch5Func('/parent/child/?status=1&type=2', '/parent/child')).toEqual(false);
  expect(util.keyMatch5Func('/parent/child?status=1&type=2', '/parent/child/')).toEqual(false);

  expect(util.keyMatch5Func('keyMatch5: expected 2 arguments, but got 1', '/foo')).toEqual(false);
  expect(util.keyMatch5Func('keyMatch5: expected 2 arguments, but got 3', '/foo/create/123', '/foo/*', '/foo/update/123')).toEqual(false);
  expect(util.keyMatch5Func('keyMatch5: argument must be a string', '/parent/123', true)).toEqual(false);

  expect(util.keyMatch5Func('/foo', '/foo')).toEqual(true);
  expect(util.keyMatch5Func('/foo', '/foo*')).toEqual(true);
  expect(util.keyMatch5Func('/foo', '/foo/*')).toEqual(false);
  expect(util.keyMatch5Func('/foo/bar', '/foo')).toEqual(false);
  expect(util.keyMatch5Func('/foo/bar', '/foo*')).toEqual(false);
  expect(util.keyMatch5Func('/foo/bar', '/foo/*')).toEqual(true);
  expect(util.keyMatch5Func('/foobar', '/foo')).toEqual(false);
  expect(util.keyMatch5Func('/foobar', '/foo*')).toEqual(false);
  expect(util.keyMatch5Func('/foobar', '/foo/*')).toEqual(false);

  expect(util.keyMatch5Func('/', '/{resource}')).toEqual(false);
  expect(util.keyMatch5Func('/resource1', '/{resource}')).toEqual(true);
  expect(util.keyMatch5Func('/myid', '/{id}/using/{resId}')).toEqual(false);
  expect(util.keyMatch5Func('/myid/using/myresid', '/{id}/using/{resId}')).toEqual(true);

  expect(util.keyMatch5Func('/proxy/myid', '/proxy/{id}/*')).toEqual(false);
  expect(util.keyMatch5Func('/proxy/myid/', '/proxy/{id}/*')).toEqual(true);
  expect(util.keyMatch5Func('/proxy/myid/res', '/proxy/{id}/*')).toEqual(true);
  expect(util.keyMatch5Func('/proxy/myid/res/res2', '/proxy/{id}/*')).toEqual(true);
  expect(util.keyMatch5Func('/proxy/myid/res/res2/res3', '/proxy/{id}/*')).toEqual(true);
  expect(util.keyMatch5Func('/proxy/', '/proxy/{id}/*')).toEqual(false);

  expect(util.keyMatch5Func('/proxy/myid?status=1&type=2', '/proxy/{id}/*')).toEqual(false);
  expect(util.keyMatch5Func('/proxy/myid/', '/proxy/{id}/*')).toEqual(true);
  expect(util.keyMatch5Func('/proxy/myid/res?status=1&type=2', '/proxy/{id}/*')).toEqual(true);
  expect(util.keyMatch5Func('/proxy/myid/res/res2?status=1&type=2', '/proxy/{id}/*')).toEqual(true);
  expect(util.keyMatch5Func('/proxy/myid/res/res2/res3?status=1&type=2', '/proxy/{id}/*')).toEqual(true);
  expect(util.keyMatch5Func('/proxy/', '/proxy/{id}/*')).toEqual(false);
});

test('test ipMatchFunc', () => {
  expect(util.ipMatchFunc('::1', '::0:1')).toEqual(true);
  expect(util.ipMatchFunc('192.168.1.1', '192.168.1.1')).toEqual(true);
  expect(util.ipMatchFunc('127.0.0.1', '::ffff:127.0.0.1')).toEqual(true);
  expect(util.ipMatchFunc('192.168.2.123', '192.168.2.0/24')).toEqual(true);
  expect(util.ipMatchFunc('::1', '127.0.0.2')).toEqual(false);
  expect(() => util.ipMatchFunc('I am alice', '127.0.0.1')).toThrow(Error);
  expect(() => util.ipMatchFunc('127.0.0.1', 'I am alice')).toThrow(/invalid/g);
  expect(util.ipMatchFunc('192.168.2.189', '192.168.1.134/26')).toEqual(false);
});

// CVE fix: IPv4 octet overflow allow-list bypass
// Before fix: 448.168.2.10 was silently reduced to 192.168.2.10 (448 & 0xff = 192),
// allowing bypass of 192.168.2.0/24 allow-lists.
test('test ipMatchFunc - IPv4 octet overflow is rejected', () => {
  // Overflowed octets must be treated as invalid IPs, not silently normalized.
  expect(() => util.ipMatchFunc('448.168.2.10', '192.168.2.0/24')).toThrow(Error);
  expect(() => util.ipMatchFunc('266.0.0.1', '10.0.0.0/16')).toThrow(Error);
  expect(() => util.ipMatchFunc('203.0.369.42', '203.0.113.0/24')).toThrow(Error);
  // Exact /32 host rule bypass: 459.0.113.42 must NOT match 203.0.113.42/32
  expect(() => util.ipMatchFunc('459.0.113.42', '203.0.113.42/32')).toThrow(Error);
  // Boundary values: 255 is valid, 256 is not
  expect(util.ipMatchFunc('10.0.255.1', '10.0.0.0/16')).toEqual(true);
  expect(() => util.ipMatchFunc('10.0.256.1', '10.0.0.0/16')).toThrow(Error);
});

// CVE fix: IPv6 CIDR matching was completely broken — any string (including "abc")
// matched any IPv6 CIDR policy due to toLong() collapsing everything to 0.
test('test ipMatchFunc - IPv6 CIDR containment is correct', () => {
  // Positive: addresses that should actually match
  expect(util.ipMatchFunc('::1', '::1/128')).toEqual(true);
  expect(util.ipMatchFunc('fe80::1', 'fe80::/10')).toEqual(true);
  expect(util.ipMatchFunc('fe80::ffff', 'fe80::/10')).toEqual(true);
  expect(util.ipMatchFunc('2001:db8::1', '2001:db8::/32')).toEqual(true);
  expect(util.ipMatchFunc('fd00::1', 'fd00::/8')).toEqual(true);

  // Negative: addresses outside the CIDR must not match
  expect(util.ipMatchFunc('fe80::1', '::1/128')).toEqual(false);
  expect(util.ipMatchFunc('ffff::1', '::1/128')).toEqual(false);
  expect(util.ipMatchFunc('::', '::1/128')).toEqual(false);
  expect(util.ipMatchFunc('2001:db8::1', 'fe80::/10')).toEqual(false);
  expect(util.ipMatchFunc('::1', 'fe80::/10')).toEqual(false);
  expect(util.ipMatchFunc('fe80::1', '2001:db8::/32')).toEqual(false);
  expect(util.ipMatchFunc('::1', '2001:db8::/32')).toEqual(false);
  expect(util.ipMatchFunc('::1', 'fd00::/8')).toEqual(false);
  expect(util.ipMatchFunc('fe80::1', 'fd00::/8')).toEqual(false);
});

// CVE fix: garbage input like "abc" must be rejected, not silently match IPv6 policies.
test('test ipMatchFunc - non-IP strings are rejected as ip1', () => {
  expect(() => util.ipMatchFunc('abc', '::1/128')).toThrow(Error);
  expect(() => util.ipMatchFunc('abc', 'fe80::/10')).toThrow(Error);
  expect(() => util.ipMatchFunc('abc', '2001:db8::/32')).toThrow(Error);
  expect(() => util.ipMatchFunc('abc', 'fd00::/8')).toThrow(Error);
  expect(() => util.ipMatchFunc('', '::1/128')).toThrow(Error);
});

test('test ip.isV4Format - octet range validation', () => {
  // Valid addresses
  expect(ip.isV4Format('0.0.0.0')).toEqual(true);
  expect(ip.isV4Format('255.255.255.255')).toEqual(true);
  expect(ip.isV4Format('192.168.1.1')).toEqual(true);
  expect(ip.isV4Format('10.0.0.1')).toEqual(true);

  // Overflowed octets must be rejected
  expect(ip.isV4Format('256.0.0.1')).toEqual(false);
  expect(ip.isV4Format('448.168.2.10')).toEqual(false);
  expect(ip.isV4Format('266.0.0.1')).toEqual(false);
  expect(ip.isV4Format('0.0.0.256')).toEqual(false);
  expect(ip.isV4Format('999.999.999.999')).toEqual(false);
});

test('test ip.isV6Format - rejects non-IPv6 strings', () => {
  // Valid IPv6 addresses
  expect(ip.isV6Format('::1')).toEqual(true);
  expect(ip.isV6Format('fe80::1')).toEqual(true);
  expect(ip.isV6Format('2001:db8::')).toEqual(true);
  expect(ip.isV6Format('::')).toEqual(true);

  // Non-IPv6 strings must be rejected (no colon present)
  expect(ip.isV6Format('abc')).toEqual(false);
  expect(ip.isV6Format('a')).toEqual(false);
  expect(ip.isV6Format('')).toEqual(false);
  expect(ip.isV6Format('192.168.1.1')).toEqual(false);
});

test('test ip.cidrSubnet - IPv6 short prefixes use 16-byte mask', () => {
  // /8, /10, /32 on IPv6 previously returned a 4-byte IPv4 mask
  expect(ip.cidrSubnet('fd00::/8').contains('fd00::1')).toEqual(true);
  expect(ip.cidrSubnet('fd00::/8').contains('fe80::1')).toEqual(false);
  expect(ip.cidrSubnet('fe80::/10').contains('fe80::1')).toEqual(true);
  expect(ip.cidrSubnet('fe80::/10').contains('::1')).toEqual(false);
  expect(ip.cidrSubnet('2001:db8::/32').contains('2001:db8::1')).toEqual(true);
  expect(ip.cidrSubnet('2001:db8::/32').contains('2001:db9::1')).toEqual(false);
  // Invalid input must not match
  expect(ip.cidrSubnet('::1/128').contains('abc')).toEqual(false);
  expect(ip.cidrSubnet('::1/128').contains('')).toEqual(false);
});

test('test globMatch', () => {
  expect(util.globMatch('/foo', '/foo')).toEqual(true);
  expect(util.globMatch('/foo', '/foo*')).toEqual(true);
  expect(util.globMatch('/foo', '/foo/*')).toEqual(false);

  expect(util.globMatch('/foo', '/foo')).toEqual(true);
  expect(util.globMatch('/foo', '/foo*')).toEqual(true);
  expect(util.globMatch('/foo', '/foo/*')).toEqual(false);
  expect(util.globMatch('/foo/bar', '/foo')).toEqual(false);
  expect(util.globMatch('/foo/bar', '/foo*')).toEqual(false);
  expect(util.globMatch('/foo/bar', '/foo/*')).toEqual(true);
  expect(util.globMatch('/foobar', '/foo')).toEqual(false);
  expect(util.globMatch('/foobar', '/foo*')).toEqual(true);
  expect(util.globMatch('/foobar', '/foo/*')).toEqual(false);

  expect(util.globMatch('/foo', '*/foo')).toEqual(true);
  expect(util.globMatch('/foo', '*/foo*')).toEqual(true);
  expect(util.globMatch('/foo', '*/foo/*')).toEqual(false);
  expect(util.globMatch('/foo/bar', '*/foo')).toEqual(false);
  expect(util.globMatch('/foo/bar', '*/foo*')).toEqual(false);
  expect(util.globMatch('/foo/bar', '*/foo/*')).toEqual(true);
  expect(util.globMatch('/foobar', '*/foo')).toEqual(false);
  expect(util.globMatch('/foobar', '*/foo*')).toEqual(true);
  expect(util.globMatch('/foobar', '*/foo/*')).toEqual(false);

  expect(util.globMatch('/prefix/foo', '*/foo')).toEqual(false);
  expect(util.globMatch('/prefix/foo', '*/foo*')).toEqual(false);
  expect(util.globMatch('/prefix/foo', '*/foo/*')).toEqual(false);
  expect(util.globMatch('/prefix/foo/bar', '*/foo')).toEqual(false);
  expect(util.globMatch('/prefix/foo/bar', '*/foo*')).toEqual(false);
  expect(util.globMatch('/prefix/foo/bar', '*/foo/*')).toEqual(false);
  expect(util.globMatch('/prefix/foobar', '*/foo')).toEqual(false);
  expect(util.globMatch('/prefix/foobar', '*/foo*')).toEqual(false);
  expect(util.globMatch('/prefix/foobar', '*/foo/*')).toEqual(false);

  expect(util.globMatch('/prefix/subprefix/foo', '*/foo')).toEqual(false);
  expect(util.globMatch('/prefix/subprefix/foo', '*/foo*')).toEqual(false);
  expect(util.globMatch('/prefix/subprefix/foo', '*/foo/*')).toEqual(false);
  expect(util.globMatch('/prefix/subprefix/foo/bar', '*/foo')).toEqual(false);
  expect(util.globMatch('/prefix/subprefix/foo/bar', '*/foo*')).toEqual(false);
  expect(util.globMatch('/prefix/subprefix/foo/bar', '*/foo/*')).toEqual(false);
  expect(util.globMatch('/prefix/subprefix/foobar', '*/foo')).toEqual(false);
  expect(util.globMatch('/prefix/subprefix/foobar', '*/foo*')).toEqual(false);
  expect(util.globMatch('/prefix/subprefix/foobar', '*/foo/*')).toEqual(false);

  expect(util.globMatch('a.conf', '*.conf')).toEqual(true);
});

test('test hasEval', () => {
  expect(util.hasEval('eval() && a && b && c')).toEqual(true);
  expect(util.hasEval('eval() && a && b && c')).toEqual(true);
  expect(util.hasEval('eval) && a && b && c')).toEqual(false);
  expect(util.hasEval('eval)( && a && b && c')).toEqual(false);
  expect(util.hasEval('xeval() && a && b && c')).toEqual(false);
  expect(util.hasEval('eval(c * (a + b)) && a && b && c')).toEqual(true);
});

test('test replaceEval', () => {
  expect(util.replaceEval('eval() && a && b && c', '', 'a')).toEqual('(a) && a && b && c');
  expect(util.replaceEval('eval() && a && b && c', '', '(a)')).toEqual('((a)) && a && b && c');
  expect(util.replaceEval('eval(p_some_rule) && c', 'p_some_rule', '(a)')).toEqual('((a)) && c');
  expect(util.replaceEval('eval(p_some_rule) && eval(p_some_other_rule) && c', 'p_some_rule', '(a)')).toEqual(
    '((a)) && eval(p_some_other_rule) && c'
  );
});

test('test getEvalValue', () => {
  expect(util.arrayEquals(util.getEvalValue('eval(a) && a && b && c'), ['a']));
  expect(util.arrayEquals(util.getEvalValue('a && eval(a) && b && c'), ['a']));
  expect(util.arrayEquals(util.getEvalValue('eval(a) && eval(b) && a && b && c'), ['a', 'b']));
  expect(util.arrayEquals(util.getEvalValue('a && eval(a) && eval(b) && b && c'), ['a', 'b']));
});

test('bracketCompatible', () => {
  expect(util.bracketCompatible("g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.obj in ('data2', 'data3')")).toEqual(
    "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.obj in ['data2', 'data3']"
  );
  expect(
    util.bracketCompatible(
      "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.obj in ('data2', 'data3') || r.obj in ('data4', 'data5')"
    )
  ).toEqual("g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.obj in ['data2', 'data3'] || r.obj in ['data4', 'data5']");
});

test('test escapeAssertion', () => {
  expect(util.escapeAssertion('r_sub == r_obj.value')).toEqual('r_sub == r_obj.value');
  expect(util.escapeAssertion('p_sub == r_sub.value')).toEqual('p_sub == r_sub.value');
  expect(util.escapeAssertion('r.attr.value == p.attr')).toEqual('r_attr.value == p_attr');
  expect(util.escapeAssertion('r.attr.value == p.attr')).toEqual('r_attr.value == p_attr');
  expect(util.escapeAssertion('r.attp.value || p.attr')).toEqual('r_attp.value || p_attr');
  expect(util.escapeAssertion('r2.attr.value == p2.attr')).toEqual('r2_attr.value == p2_attr');
  expect(util.escapeAssertion('r2.attp.value || p2.attr')).toEqual('r2_attp.value || p2_attr');
  expect(util.escapeAssertion('r.attp.value &&p.attr')).toEqual('r_attp.value &&p_attr');
  expect(util.escapeAssertion('r.attp.value >p.attr')).toEqual('r_attp.value >p_attr');
  expect(util.escapeAssertion('r.attp.value <p.attr')).toEqual('r_attp.value <p_attr');
  expect(util.escapeAssertion('r.attp.value +p.attr')).toEqual('r_attp.value +p_attr');
  expect(util.escapeAssertion('r.attp.value -p.attr')).toEqual('r_attp.value -p_attr');
  expect(util.escapeAssertion('r.attp.value *p.attr')).toEqual('r_attp.value *p_attr');
  expect(util.escapeAssertion('r.attp.value /p.attr')).toEqual('r_attp.value /p_attr');
  expect(util.escapeAssertion('!r.attp.value /p.attr')).toEqual('!r_attp.value /p_attr');
  expect(util.escapeAssertion('g(r.sub, p.sub) == p.attr')).toEqual('g(r_sub, p_sub) == p_attr');
  expect(util.escapeAssertion('g(r.sub,p.sub) == p.attr')).toEqual('g(r_sub,p_sub) == p_attr');
  expect(util.escapeAssertion('(r.attp.value || p.attr)p.u')).toEqual('(r_attp.value || p_attr)p_u');
  // Test that patterns inside strings are not escaped
  expect(util.escapeAssertion('r.sub == "a.p.p.l.e"')).toEqual('r_sub == "a.p.p.l.e"');
  expect(util.escapeAssertion('r.sub == "test.p.value"')).toEqual('r_sub == "test.p.value"');
});
