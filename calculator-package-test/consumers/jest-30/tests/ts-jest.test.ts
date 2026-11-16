import { baseOf } from '../src/from-vector';
import { severityToNumber } from '../src/named-classes';

describe('ts-jest with the real calculator', () => {
  it('scores through fromVector', () => {
    expect(baseOf('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
  });

  it('scores through the named classes', () => {
    expect(severityToNumber('CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H')).toBe(5.9);
  });

  it('passes plain numbers through', () => {
    expect(severityToNumber('4.2')).toBe(4.2);
  });
});
