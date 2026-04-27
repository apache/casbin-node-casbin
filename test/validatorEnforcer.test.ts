import { ValidatorEnforcer } from '../src/validatorEnforcer';

describe('ValidatorEnforcer', () => {
  describe('validateMatcher', () => {
    it('should not throw error for valid matcher', () => {
      expect(() => {
        ValidatorEnforcer.validateMatcher('r.sub == p.sub && r.obj == p.obj && r.act == p.act');
      }).not.toThrow();
    });

    it('should throw error for invalid properties', () => {
      expect(() => {
        ValidatorEnforcer.validateMatcher('r.invalid == p.sub');
      }).toThrow('Invalid properties: r.invalid');
    });

    it('should throw error for extra dots', () => {
      expect(() => {
        ValidatorEnforcer.validateMatcher('r..sub == p.sub');
      }).toThrow('Found extra dots');
    });

    it('should throw error for unnecessary comma', () => {
      expect(() => {
        ValidatorEnforcer.validateMatcher('r.sub == p.sub,');
      }).toThrow('Unnecessary comma');
    });

    it('should throw error for mismatched parentheses', () => {
      expect(() => {
        ValidatorEnforcer.validateMatcher('(r.sub == p.sub');
      }).toThrow('Mismatched parentheses');
    });

    it('should throw error for invalid operators', () => {
      expect(() => {
        ValidatorEnforcer.validateMatcher('r.sub & p.sub');
      }).toThrow('Invalid operator in matcher');
    });
  });

  describe('validatePolicyPriority', () => {
    it('should not throw error for same priority', () => {
      expect(() => {
        ValidatorEnforcer.validatePolicyPriority(['alice', 'data1', 'read', '1'], ['bob', 'data2', 'write', '1'], 3);
      }).not.toThrow();
    });

    it('should throw error for different priority', () => {
      expect(() => {
        ValidatorEnforcer.validatePolicyPriority(['alice', 'data1', 'read', '1'], ['bob', 'data2', 'write', '2'], 3);
      }).toThrow('new rule should have the same priority with old rule.');
    });
  });

  describe('validateRequiredSections', () => {
    it('should not throw error when all required sections are present', () => {
      const model = new Map([
        ['r', new Map()],
        ['p', new Map()],
        ['e', new Map()],
        ['m', new Map()],
      ]);
      expect(() => {
        ValidatorEnforcer.validateRequiredSections(model);
      }).not.toThrow();
    });

    it('should throw error when required sections are missing', () => {
      const model = new Map([
        ['r', new Map()],
        ['p', new Map()],
      ]);
      expect(() => {
        ValidatorEnforcer.validateRequiredSections(model);
      }).toThrow('missing required sections: policy_effect,matchers');
    });
  });
});
