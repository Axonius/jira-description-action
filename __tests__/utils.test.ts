import { HIDDEN_MARKER_END, HIDDEN_MARKER_START, WARNING_MESSAGE_ABOUT_HIDDEN_MARKERS } from '../src/constants';
import { getJIRAIssueKeyByDefaultRegexp, getJIRAIssueKeysByCustomRegexp, getPRDescription, sanitizeHttpValue, shouldSkipBranch } from '../src/utils';

jest.spyOn(console, 'log').mockImplementation(); // avoid actual console.log in test output

describe('shouldSkipBranch()', () => {
  it('should recognize bot PRs', () => {
    expect(shouldSkipBranch('dependabot/npm_and_yarn/types/react-dom-16.9.6')).toBe(true);
    expect(shouldSkipBranch('feature/add-dependabot-config')).toBe(false);
  });

  it('should handle custom ignore patterns', () => {
    expect(shouldSkipBranch('bar', '^bar')).toBeTruthy();
    expect(shouldSkipBranch('foobar', '^bar')).toBeFalsy();

    expect(shouldSkipBranch('bar', '[0-9]{2}')).toBeFalsy();
    expect(shouldSkipBranch('bar', '')).toBeFalsy();
    expect(shouldSkipBranch('f00', '[0-9]{2}')).toBeTruthy();

    const customBranchRegex = '^(production-release|master|release/v\\d+)$';

    expect(shouldSkipBranch('production-release', customBranchRegex)).toBeTruthy();
    expect(shouldSkipBranch('master', customBranchRegex)).toBeTruthy();
    expect(shouldSkipBranch('release/v77', customBranchRegex)).toBeTruthy();

    expect(shouldSkipBranch('release/very-important-feature', customBranchRegex)).toBeFalsy();
    expect(shouldSkipBranch('')).toBeFalsy();
  });
});

describe('getJIRAIssueKeys()', () => {
  it('gets jira key from different strings', () => {
    expect(getJIRAIssueKeyByDefaultRegexp('fix/login-protocol-es-43')).toEqual('ES-43');
    expect(getJIRAIssueKeyByDefaultRegexp('fix/login-protocol-ES-43')).toEqual('ES-43');
    expect(getJIRAIssueKeyByDefaultRegexp('[ES-43, ES-15] Feature description')).toEqual('ES-43');

    expect(getJIRAIssueKeyByDefaultRegexp('feature/missingKey')).toEqual(null);
    expect(getJIRAIssueKeyByDefaultRegexp('')).toEqual(null);
  });
});

describe('getJIRAIssueKeysByCustomRegexp() gets jira keys from different strings', () => {
  it('with project name', () => {
    expect(getJIRAIssueKeysByCustomRegexp('law-18,345', '^LAW-??(\\d+)', 'LAW')).toEqual('LAW-18');
    //expect(getJIRAIssueKeysByCustomRegexp('fix/login-protocol-es-43', '^\\d+', 'QQ')).toEqual(null);
    //expect(getJIRAIssueKeysByCustomRegexp('43-login-protocol', '^\\d+', 'QQ')).toEqual('QQ-43');
  });

  it('without project name', () => {
    expect(getJIRAIssueKeysByCustomRegexp('18,345', '\\d+')).toEqual('18');
    expect(getJIRAIssueKeysByCustomRegexp('fix/login-protocol-es-43', 'es-\\d+')).toEqual('ES-43');
  });

  it('with grouped value in regexp', () => {
    expect(getJIRAIssueKeysByCustomRegexp('fix/login-protocol-es-43', '(es-\\d+)$')).toEqual('ES-43');
    expect(getJIRAIssueKeysByCustomRegexp('fix/login-20-in-14', '-(IN-\\d+)')).toEqual('IN-14');
    expect(getJIRAIssueKeysByCustomRegexp('fix/login-20-in-14', 'in-(\\d+)', 'PRJ')).toEqual('PRJ-20');
  });
});

describe('getPRDescription()', () => {
  it('should prepend issue info with hidden markers to old PR body', () => {
    const oldPRBody = 'old PR description body';
    const issueInfo = 'new info about jira task';
    const description = getPRDescription(oldPRBody, issueInfo);

    expect(description).toEqual(`${WARNING_MESSAGE_ABOUT_HIDDEN_MARKERS}
${HIDDEN_MARKER_START}
${issueInfo}
${HIDDEN_MARKER_END}
${oldPRBody}`);
  });

  it('should replace issue info', () => {
    const oldPRBodyInformation = 'old PR description body';
    const oldPRBody = `${HIDDEN_MARKER_START}Here is some old issue information${HIDDEN_MARKER_END}${oldPRBodyInformation}`;
    const issueInfo = 'new info about jira task';

    const description = getPRDescription(oldPRBody, issueInfo);

    expect(description).toEqual(`${WARNING_MESSAGE_ABOUT_HIDDEN_MARKERS}
${HIDDEN_MARKER_START}
${issueInfo}
${HIDDEN_MARKER_END}
${oldPRBodyInformation}`);
  });
});

describe('sanitizeHttpValue()', () => {
  it('leaves ordinary values untouched', () => {
    expect(sanitizeHttpValue('user@example.com:abc123')).toEqual('user@example.com:abc123');
    expect(sanitizeHttpValue('https://company.atlassian.net')).toEqual('https://company.atlassian.net');
    expect(sanitizeHttpValue('ES-43')).toEqual('ES-43');
  });

  it('strips CR, LF and CRLF sequences (CWE-113 / CVE-2026-40175)', () => {
    expect(sanitizeHttpValue('abc\r\nX-Injected: 1')).toEqual('abcX-Injected: 1');
    expect(sanitizeHttpValue('abc\rdef')).toEqual('abcdef');
    expect(sanitizeHttpValue('abc\ndef')).toEqual('abcdef');
    expect(sanitizeHttpValue('\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n')).not.toMatch(/[\r\n]/);
  });

  it('strips other ASCII control characters', () => {
    expect(sanitizeHttpValue('abc\u0000def\u001fghi\u007f')).toEqual('abcdefghi');
  });

  it('trims surrounding whitespace and handles empty input', () => {
    expect(sanitizeHttpValue('  token  ')).toEqual('token');
    expect(sanitizeHttpValue('')).toEqual('');
    expect(sanitizeHttpValue(null)).toEqual('');
    expect(sanitizeHttpValue(undefined)).toEqual('');
  });
});
