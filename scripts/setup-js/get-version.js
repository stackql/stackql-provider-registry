import { exec } from 'node:child_process';

const version = `v${process.env['REG_COMMIT_YEAR']}.${process.env['REG_COMMIT_MONTH']}.${process.env['REG_PR_NO'].padStart(5, '0')}`;

console.log(`REG_VERSION: ${version}`);

exec(`echo "REG_VERSION=${version}" >> $GITHUB_ENV`);
