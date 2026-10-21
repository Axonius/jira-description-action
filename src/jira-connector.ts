import axios, { AxiosInstance } from 'axios';
import { getInputs } from './action-inputs';
import { JIRA, JIRADetails } from './types';
import { sanitizeHttpValue } from './utils';

export class JiraConnector {
  client: AxiosInstance;
  JIRA_TOKEN: string;
  JIRA_BASE_URL: string;

  constructor() {
    const { JIRA_TOKEN, JIRA_BASE_URL } = getInputs();

    this.JIRA_BASE_URL = JIRA_BASE_URL;
    this.JIRA_TOKEN = JIRA_TOKEN;

    const encodedToken = Buffer.from(JIRA_TOKEN).toString('base64');

    this.client = axios.create({
      baseURL: `${JIRA_BASE_URL}/rest/api/3`,
      timeout: 2000,
      // Header values are sanitized before reaching axios (CVE-2026-40175 / CWE-113):
      // base64 output never contains CR/LF, and sanitizeHttpValue is a second guard.
      headers: { Authorization: sanitizeHttpValue(`Basic ${encodedToken}`) },
    });
  }

  async getTicketDetails(key: string): Promise<JIRADetails> {
    console.log(`Fetching ${key} details from JIRA`);

    try {
      const issue: JIRA.Issue = await this.getIssue(key);
      const {
        fields: { issuetype: type, project, summary },
      } = issue;

      return {
        key,
        summary,
        url: `${this.JIRA_BASE_URL}/browse/${key}`,
        type: {
          name: type.name,
          icon: type.iconUrl,
        },
        project: {
          name: project.name,
          url: `${this.JIRA_BASE_URL}/browse/${project.key}`,
          key: project.key,
        },
      };
    } catch (error: any) {
      throw error;
    }
  }

  async getIssue(id: string): Promise<JIRA.Issue> {
    // Sanitize + URL-encode the key so it cannot inject CR/LF or extra path/query segments.
    const safeId = encodeURIComponent(sanitizeHttpValue(id));
    const url = `/issue/${safeId}?fields=project,summary,issuetype`;
    const response = await this.client.get<JIRA.Issue>(url);
    return response.data;
  }
}
