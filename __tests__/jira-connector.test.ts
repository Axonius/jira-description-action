import { JiraConnector } from '../src/jira-connector';

jest.mock('../src/action-inputs', () => ({
  getInputs: () => ({
    JIRA_TOKEN: 'user@example.com:secret',
    JIRA_BASE_URL: 'https://company.atlassian.net',
  }),
}));

jest.spyOn(console, 'log').mockImplementation(); // avoid actual console.log in test output

describe('JiraConnector', () => {
  it('never sends CR/LF in the Authorization header', () => {
    const connector = new JiraConnector();
    const auth = connector.client.defaults.headers.Authorization as string;
    expect(auth).toMatch(/^Basic [A-Za-z0-9+/=]+$/);
    expect(auth).not.toMatch(/[\r\n]/);
  });

  it('sanitizes and URL-encodes the issue key before requesting it', async () => {
    const connector = new JiraConnector();
    const getSpy = jest.spyOn(connector.client, 'get').mockResolvedValue({ data: {} } as any);

    await connector.getIssue('ES-43\r\nHost: 169.254.169.254\r\n\r\nGET /../admin');

    expect(getSpy).toHaveBeenCalledTimes(1);
    const requestedUrl = getSpy.mock.calls[0][0] as string;
    expect(requestedUrl).not.toMatch(/[\r\n]/);
    expect(requestedUrl).toEqual('/issue/ES-43Host%3A%20169.254.169.254GET%20%2F..%2Fadmin?fields=project,summary,issuetype');
  });
});
