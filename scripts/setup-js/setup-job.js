import * as core from '@actions/core';
import * as github from '@actions/github';

// subject line of a GitHub generated merge commit, e.g.
//   Merge pull request #11 from stackql/feature/testing2
//   Merge pull request #11 from stackql/feature/testing2 [skip ci]
const MERGE_COMMIT_RE = /^Merge pull request #(\d+) from (\S+)/;
// subject line of a GitHub generated squash merge commit, e.g.
//   some pull request title (#11)
const SQUASH_COMMIT_RE = /\(#(\d+)\)\s*$/;

function requireDigits(name, value) {
  if (!/^\d+$/.test(String(value))) {
    throw new Error(`${name} must be numeric, got: ${JSON.stringify(value)}`);
  }
  return String(value);
}

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
      targetBranch = context.payload.ref.replace('refs/heads/', '');
      const mergeMatch = MERGE_COMMIT_RE.exec(message);
      const squashMatch = SQUASH_COMMIT_RE.exec(message);
      if (mergeMatch) {
        prNumber = mergeMatch[1];
        sourceBranch = mergeMatch[2];
        const ownerPrefix = `${context.repo.owner}/`;
        if (sourceBranch.startsWith(ownerPrefix)) {
          sourceBranch = sourceBranch.substring(ownerPrefix.length);
        }
      } else if (squashMatch) {
        prNumber = squashMatch[1];
        sourceBranch = '';
      } else {
        core.setFailed(`Unable to determine pull request number from commit message: ${message}`);
        return;
      }
    } else {
      core.setFailed(`Unsupported event: ${eventName}`);
      return;
    }
    prNumber = requireDigits('pull request number', prNumber);

    // branch names, pull request titles and commit messages are contributor
    // controlled. exportVariable appends to $GITHUB_ENV using a heredoc
    // delimiter; nothing here is passed through a shell.
    core.exportVariable('REG_EVENT', eventName);
    core.exportVariable('REG_SHA', shortSha);
    core.exportVariable('REG_COMMIT_SHA', commitSha);
    core.exportVariable('REG_BASE_SHA', baseSha);
    core.exportVariable('REG_ACTION', action);
    core.exportVariable('REG_PR_NO', prNumber);
    core.exportVariable('REG_SOURCE_BRANCH', sourceBranch);
    core.exportVariable('REG_TARGET_BRANCH', targetBranch);
  } catch (error) {
    core.setFailed(error.message);
    return;
  }
}

await run();
