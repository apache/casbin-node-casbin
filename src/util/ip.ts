// This is a minimal subset of node-ip for handling IPMatch
// https://github.com/indutny/node-ip/blob/master/lib/ip.js
//
// ### License
//
// This software is licensed under the MIT License.
//
// Copyright Fedor Indutny, 2012.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

import { Buffer } from 'buffer/';

const ipv4Regex = /^(25[0-5]|2[0-4]\d|1\d\d|\d?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|\d?\d)){3}$/;
const ipv6Regex = /^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i;

export const ip = {
  toBuffer: function (ip: string, buff?: Buffer, offset?: number): Buffer {
    offset = offset ? offset : 0;

    let result;

    if (this.isV4Format(ip)) {
      result = buff || new Buffer(offset + 4);
      ip.split(/\./g).map(function (byte) {
        offset = offset ? offset : 0;
        result[offset++] = parseInt(byte, 10) & 0xff;
      });
    } else if (this.isV6Format(ip)) {
      const sections = ip.split(':', 8);

      let i;
      for (i = 0; i < sections.length; i++) {
        const isv4 = this.isV4Format(sections[i]);

        let v4Buffer;

        if (isv4) {
          v4Buffer = this.toBuffer(sections[i]);
          sections[i] = v4Buffer.slice(0, 2).toString('hex');
        }

        if (v4Buffer && ++i < 8) {
          sections.splice(i, 0, v4Buffer.slice(2, 4).toString('hex'));
        }
      }

      if (sections[0] === '') {
        while (sections.length < 8) sections.unshift('0');
      } else if (sections[sections.length - 1] === '') {
        while (sections.length < 8) sections.push('0');
      } else if (sections.length < 8) {
        for (i = 0; i < sections.length && sections[i] !== ''; i++) {}
        const argv = [i, 1];
        for (i = 9 - sections.length; i > 0; i--) {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          argv.push('0');
        }
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        // eslint-disable-next-line prefer-spread
        sections.splice.apply(sections, argv);
      }

      result = buff || new Buffer(offset + 16);
      for (i = 0; i < sections.length; i++) {
        const word = parseInt(sections[i], 16);
        result[offset++] = (word >> 8) & 0xff;
        result[offset++] = word & 0xff;
      }
    }

    if (!result) {
      throw Error('Invalid ip address: ' + ip);
    }

    return result;
  },
  toString: function (buff: Buffer, offset?: number, length?: number): string {
    offset = offset ? offset : 0;
    length = length || buff.length - offset;

    let result = [];
    if (length === 4) {
      // IPv4
      for (let i = 0; i < length; i++) {
        result.push(buff[offset + i]);
      }
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      result = result.join('.');
    } else if (length === 16) {
      // IPv6
      for (let i = 0; i < length; i += 2) {
        result.push(buff.readUInt16BE(offset + i).toString(16));
      }
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      result = result.join(':');
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      result = (result as string).replace(/(^|:)0(:0)*:0(:|$)/, '$1::$3');
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      result = (result as string).replace(/:{3,4}/, '::');
    }
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    return result as string;
  },
  isV4Format: function (ip: string): boolean {
    return ipv4Regex.test(ip);
  },

  isV6Format: function (ip: string): boolean {
    return ip.includes(':') && ipv6Regex.test(ip);
  },

  fromPrefixLen: function (prefixlen: number, family?: string): string {
    family = _normalizeFamily(typeof family === 'string' ? family : 'ipv4');
    if (prefixlen > 32) {
      family = 'ipv6';
    }

    let len = 4;
    if (family === 'ipv6') {
      len = 16;
    }
    const buff = new Buffer(len);

    for (let i = 0, n = buff.length; i < n; ++i) {
      let bits = 8;
      if (prefixlen < 8) {
        bits = prefixlen;
      }
      prefixlen -= bits;

      buff[i] = ~(0xff >> bits) & 0xff;
    }

    return ip.toString(buff);
  },

  mask: function (addr: string, mask: string): string {
    const addrBuffer = ip.toBuffer(addr);
    const maskBuffer = ip.toBuffer(mask);

    const result = new Buffer(Math.max(addrBuffer.length, maskBuffer.length));

    let i;
    // Same protocol - do bitwise and
    if (addrBuffer.length === maskBuffer.length) {
      for (i = 0; i < addrBuffer.length; i++) {
        result[i] = addrBuffer[i] & maskBuffer[i];
      }
    } else if (maskBuffer.length === 4) {
      // IPv6 address and IPv4 mask
      // (Mask low bits)
      for (i = 0; i < maskBuffer.length; i++) {
        result[i] = addrBuffer[addrBuffer.length - 4 + i] & maskBuffer[i];
      }
    } else {
      // IPv6 mask and IPv4 addr
      for (let i = 0; i < result.length - 6; i++) {
        result[i] = 0;
      }

      // ::ffff:ipv4
      result[10] = 0xff;
      result[11] = 0xff;
      for (i = 0; i < addrBuffer.length; i++) {
        result[i + 12] = addrBuffer[i] & maskBuffer[i + 12];
      }
      i = i + 12;
    }
    for (; i < result.length; i++) result[i] = 0;

    return ip.toString(result);
  },

  subnet: function (addr: string, mask: string): any {
    const networkBuffer = ip.toBuffer(ip.mask(addr, mask));

    // Calculate the mask's length.
    const maskBuffer = ip.toBuffer(mask);
    let maskLength = 0;

    for (let i = 0; i < maskBuffer.length; i++) {
      if (maskBuffer[i] === 0xff) {
        maskLength += 8;
      } else {
        let octet = maskBuffer[i] & 0xff;
        while (octet) {
          octet = (octet << 1) & 0xff;
          maskLength++;
        }
      }
    }

    return {
      contains: function (other: string) {
        let otherBuffer: Buffer;
        try {
          otherBuffer = ip.toBuffer(ip.mask(other, mask));
        } catch {
          return false;
        }
        if (networkBuffer.length !== otherBuffer.length) return false;
        for (let i = 0; i < networkBuffer.length; i++) {
          if (networkBuffer[i] !== otherBuffer[i]) return false;
        }
        return true;
      },
    };
  },
  cidrSubnet: function (cidrString: string): any {
    const cidrParts = cidrString.split('/');

    const addr = cidrParts[0];
    if (cidrParts.length !== 2) throw new Error('invalid CIDR subnet: ' + addr);

    const family = ip.isV6Format(addr) ? 'ipv6' : 'ipv4';
    const mask = ip.fromPrefixLen(parseInt(cidrParts[1], 10), family);

    return ip.subnet(addr, mask);
  },
  isEqual: function (a: string, b: string): boolean {
    let aBuffer = ip.toBuffer(a);
    let bBuffer = ip.toBuffer(b);

    // Same protocol
    if (aBuffer.length === bBuffer.length) {
      for (let i = 0; i < aBuffer.length; i++) {
        if (aBuffer[i] !== bBuffer[i]) return false;
      }
      return true;
    }

    // Swap
    if (bBuffer.length === 4) {
      const t = bBuffer;
      bBuffer = aBuffer;
      aBuffer = t;
    }

    // a - IPv4, b - IPv6
    for (let i = 0; i < 10; i++) {
      if (bBuffer[i] !== 0) return false;
    }

    const word = bBuffer.readUInt16BE(10);
    if (word !== 0 && word !== 0xffff) return false;

    for (let i = 0; i < 4; i++) {
      if (aBuffer[i] !== bBuffer[i + 12]) return false;
    }

    return true;
  },
  toLong: function (ip: string): number {
    let ipl = 0;
    ip.split('.').forEach(function (octet) {
      ipl <<= 8;
      ipl += parseInt(octet);
    });
    return ipl >>> 0;
  },
  fromLong: function (ipl: number): string {
    return (ipl >>> 24) + '.' + ((ipl >> 16) & 255) + '.' + ((ipl >> 8) & 255) + '.' + (ipl & 255);
  },
};

function _normalizeFamily(family: string): string {
  return family ? family.toLowerCase() : 'ipv4';
}
