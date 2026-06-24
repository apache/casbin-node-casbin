import { sectionNameMap, requiredSections } from './model/model';

export class ValidatorEnforcer {
  // Verify matcher
  public static validateMatcher(matcherStr: string): void {
    const errors: string[] = [];

    const validProps = ['r.sub', 'r.obj', 'r.act', 'r.dom', 'p.sub', 'p.obj', 'p.act', 'p.dom', 'p.eft', 'p.sub_rule'];
    const usedProps = matcherStr.match(/[rp]\.\w+/g) || [];
    const invalidProps = usedProps.filter((prop) => !validProps.includes(prop));
    if (invalidProps.length > 0) {
      errors.push(`Invalid properties: ${invalidProps.join(', ')}`);
    }

    if (matcherStr.includes('..')) {
      errors.push('Found extra dots');
    }

    if (matcherStr.trim().endsWith(',')) {
      errors.push('Unnecessary comma');
    }

    const openBrackets = (matcherStr.match(/\(/g) || []).length;
    const closeBrackets = (matcherStr.match(/\)/g) || []).length;
    if (openBrackets !== closeBrackets) {
      errors.push('Mismatched parentheses');
    }

    const invalidOperators = /(?<![&|])&(?!&)|(?![&|])\|(?!\|)|&{3,}|\|{3,}/g;
    if (invalidOperators.test(matcherStr)) {
      errors.push('Invalid operator in matcher');
    }

    if (errors.length > 0) {
      throw new Error(`${errors.join(', ')}`);
    }
  }

  // Verify policy priority
  public static validatePolicyPriority(oldRule: string[], newRule: string[], priorityIndex: number): void {
    if (oldRule[priorityIndex] !== newRule[priorityIndex]) {
      throw new Error('new rule should have the same priority with old rule.');
    }
  }

  // Verify required sections
  public static validateRequiredSections(model: Map<string, Map<string, any>>): void {
    const missingSections = requiredSections.filter((section) => !model.has(section));

    if (missingSections.length > 0) {
      const missingNames = missingSections.map((s) => sectionNameMap[s]);
      throw new Error(`missing required sections: ${missingNames.join(',')}`);
    }
  }

  // Verify duplicate section
  public static validateDuplicateSection(section: string, lineNumber: number): void {
    throw new Error(`Duplicated section: ${section} at line ${lineNumber}`);
  }

  // Verify content parse
  public static validateContentParse(lineNum: number): void {
    throw new Error(`parse the content error : line ${lineNum}`);
  }

  // Verify empty key
  public static validateEmptyKey(): void {
    throw new Error('key is empty');
  }

  // Verify operator in matcher
  public static validateMatcherOperators(value: string): void {
    const invalidOperators = /(?<![&|])&(?!&)|(?![&|])\|(?!\|)|&{3,}|\|{3,}/g;
    if (invalidOperators.test(value)) {
      throw new Error(`Invalid operator in matcher`);
    }
  }

  // Verify model parameters
  public static validateModelParameters(textLength: number): void {
    if (textLength !== 0 && textLength !== 1 && textLength !== 2) {
      throw new Error('Invalid parameters for model');
    }
  }
}
