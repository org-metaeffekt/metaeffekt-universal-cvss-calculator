import { baseOfRating } from '../../src/handlers/vulnerabilities';

describe('baseOfRating with the real calculator', () => {
  test('scores CVSS 3.1', () => {
    expect(baseOfRating({ version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' })).toBe(9.8);
  });

  test('scores CVSS 4.0', () => {
    expect(baseOfRating({ version: '4.0', vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H' })).toBe(5.9);
  });
});
