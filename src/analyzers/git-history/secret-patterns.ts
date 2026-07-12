export type HistoricalSecretPattern = {
  id: string;
  title: string;
  severity:
    | 'critical'
    | 'high'
    | 'medium';
  regex: RegExp;
};

export const historicalSecretPatterns:
  HistoricalSecretPattern[] = [
    {
      id: 'TLP-GIT-101',
      title: 'GitHub token in Git history',
      severity: 'critical',
      regex:
        /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g
    },
    {
      id: 'TLP-GIT-102',
      title: 'npm token in Git history',
      severity: 'critical',
      regex:
        /\bnpm_[A-Za-z0-9]{20,}\b/g
    },
    {
      id: 'TLP-GIT-103',
      title: 'AWS access key in Git history',
      severity: 'critical',
      regex:
        /\bAKIA[0-9A-Z]{16}\b/g
    },
    {
      id: 'TLP-GIT-104',
      title: 'Private key in Git history',
      severity: 'critical',
      regex:
        /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g
    },
    {
      id: 'TLP-GIT-105',
      title: 'Password assignment in Git history',
      severity: 'high',
      regex:
        /\b(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi
    }
  ];
