## 0.3.3
* Security: bump `axios` to `^0.31.0` (CVE-2026-40175 / GHSA-fvcv-3m26-pcqx, CRLF header injection)
* Security: strip CR/LF and control characters from `jira-token`, `jira-base-url`, `github-token`, `jira-project-key` and the issue key before they reach HTTP headers / URLs

## 0.3.1
* Don't fail if PR body is empty fixing https://github.com/cakeinpanic/jira-description-action/issues/17

## 0.3.0
* Add `fail-when-jira-issue-not-found` input

## 0.2.0
* Replace `use-branch-name` with `use`

## 0.1.2
* Add regexp groups support
* Allow usage without project name

## 0.1.1
* Don't make user to base64 encode his token manually
* Remove auto-build of action itself for tags and fix target branch for non-master branches

## 0.1.0
* Release first version
