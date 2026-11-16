describe('toJson', () => {
    afterEach(() => {
        jest.dontMock('ae-cvss-calculator');
        jest.resetModules();
    });

    it('can be pointed at a fake calculator with jest.doMock', () => {
        const fakeType = (score) => jest.fn().mockImplementation(() => ({
            createJsonSchema: () => ({ baseScore: score })
        }));
        jest.doMock('ae-cvss-calculator', () => ({ Cvss3P1: fakeType(1.5), Cvss4P0: fakeType(2.5) }));

        const { toJson } = require('../src/to-json');
        expect(toJson(3, 'ignored').baseScore).toBe(1.5);
        expect(toJson(4, 'ignored').baseScore).toBe(2.5);
    });

    it('uses the real calculator again after jest.dontMock', () => {
        const { toJson } = require('../src/to-json');
        expect(toJson(3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').baseScore).toBe(9.8);
        expect(toJson(4, 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H').baseScore).toBe(5.9);
    });
});
