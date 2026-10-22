import * as core from '@actions/core';
import { ESource, IActionInputs } from './types';
import { sanitizeHttpValue } from './utils';

export const getInputs = (): IActionInputs => {
  try {
    // Strip CR/LF and control chars: these values end up in HTTP headers / URLs (CVE-2026-40175, CWE-113).
    const JIRA_TOKEN: string = sanitizeHttpValue(core.getInput('jira-token', { required: true }));
    const JIRA_BASE_URL: string = sanitizeHttpValue(core.getInput('jira-base-url', { required: true }));
    const GITHUB_TOKEN: string = sanitizeHttpValue(core.getInput('github-token', { required: true }));
    const BRANCH_IGNORE_PATTERN: string = core.getInput('skip-branches', { required: false }) || '';
    const CUSTOM_ISSUE_NUMBER_REGEXP = core.getInput('custom-issue-number-regexp', { required: false });
    const JIRA_PROJECT_KEY = sanitizeHttpValue(core.getInput('jira-project-key', { required: false }));
    const FAIL_WHEN_JIRA_ISSUE_NOT_FOUND = core.getInput('fail-when-jira-issue-not-found', { required: false }) === 'true' || false;
    const WHAT_TO_USE: ESource = (core.getInput('use', { required: false }) as ESource) || ESource.prTitle;

    return {
      JIRA_TOKEN,
      GITHUB_TOKEN,
      WHAT_TO_USE,
      BRANCH_IGNORE_PATTERN,
      JIRA_PROJECT_KEY,
      CUSTOM_ISSUE_NUMBER_REGEXP,
      FAIL_WHEN_JIRA_ISSUE_NOT_FOUND,
      JIRA_BASE_URL: JIRA_BASE_URL.endsWith('/') ? JIRA_BASE_URL.replace(/\/$/, '') : JIRA_BASE_URL,
    };
  } catch (error: any) {
    core.error(error.message);
    process.exit(1);
  }
};
