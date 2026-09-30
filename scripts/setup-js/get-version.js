import * as core from '@actions/core';

function requireDigits(name, value) {
  if (!/^\d+$/.test(String(value))) {
    throw new Error(`${name} must be numeric, got: ${JSON.stringify(value)}`);
  }
  return String(value);
}

try {
  const year = requireDigits('REG_COMMIT_YEAR', process.env['REG_COMMIT_YEAR']);
  const month = requireDigits('REG_COMMIT_MONTH', process.env['REG_COMMIT_MONTH']);
  const prNumber = requireDigits('REG_PR_NO', process.env['REG_PR_NO']);

  const version = `v${year}.${month}.${prNumber.padStart(5, '0')}`;

  console.log(`REG_VERSION: ${version}`);

  // written to $GITHUB_ENV with a heredoc delimiter, not through a shell
  core.exportVariable('REG_VERSION', version);
} catch (error) {
  core.setFailed(error.message);
}
