import * as core from '@actions/core';
import * as github from '@actions/github';
import { exec } from 'node:child_process';

async function run() {
  try {
    const context = github.context;
    const eventName = context.eventName;
    const commitSha = context.sha;
    const shortSha = commitSha.substring(0, 7);
    let action;
    let baseSha;
    let prNumber;
    let message;
    let sourceBranch;
    let targetBranch;
    if(eventName == 'pull_request') {
      action = context.payload.action;
      baseSha = context.payload.pull_request.base.sha;
      prNumber = context.payload.number;
      message = context.payload.pull_request.title;
      sourceBranch = context.payload.pull_request.head.ref;
      targetBranch = context.payload.pull_request.base.ref;
    } else if(eventName == 'push') {
      action = '';
      baseSha = context.payload.before;
      message = context.payload.head_commit.message.split('\n')[0];
      console.log(`Commit Message: ${message}`);
      // Merge pull request #11 from stackql/feature/testing2
      const commitMessageParts = message.split(' ');
      prNumber = commitMessageParts[3].split('#')[1];
      sourceBranch = commitMessageParts[5].replace(`${context.payload.organization.login}/`, '');
      targetBranch = context.payload.ref.replace('refs/heads/', '');
      // console.log(JSON.stringify(context, undefined, 2));
    } else {
      core.setFailed(`Unsupported event: ${eventName}`);
      return;
    }
    exec(`echo "REG_EVENT=${eventName}" >> $GITHUB_ENV`);
    exec(`echo "REG_SHA=${shortSha}" >> $GITHUB_ENV`);
    exec(`echo "REG_COMMIT_SHA=${commitSha}" >> $GITHUB_ENV`);
    exec(`echo "REG_BASE_SHA=${baseSha}" >> $GITHUB_ENV`);
    exec(`echo "REG_ACTION=${action}" >> $GITHUB_ENV`);
    exec(`echo "REG_PR_NO=${prNumber}" >> $GITHUB_ENV`);
    exec(`echo "REG_SOURCE_BRANCH=${sourceBranch}" >> $GITHUB_ENV`);
    exec(`echo "REG_TARGET_BRAMCH=${targetBranch}" >> $GITHUB_ENV`);
  } catch (error) {
    core.setFailed(error.message);
    return;
  }
}

await run();
