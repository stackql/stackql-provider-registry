#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const MANIFEST_URL = 'https://registry.stackql.app/providers/dist/providers.yaml';
const TOC_MARKER = 'TABLE OF CONTENTS';
const CATALOG_MARKER = 'PROVIDER CATALOG';

// Display names and icons from stackql.io's provider tiles, keyed by source directory.
const PROVIDERS = {
  anthropic: ['Anthropic', 'anthropic.png'],
  anthropic_admin: ['Anthropic Admin', 'anthropic.png'],
  aws: ['Amazon Web Services', 'aws.ico'],
  awscc: ['AWS Cloud Control', 'aws.ico'],
  azure: ['Microsoft Azure', 'azure.ico'],
  azure_extras: ['Azure Extras', 'azure.ico'],
  azure_isv: ['Azure ISV', 'azure.ico'],
  azure_stack: ['Azure Stack', 'azure.ico'],
  clickhouse: ['ClickHouse', 'clickhouse.ico'],
  cloudflare: ['Cloudflare', 'cloudflare.ico'],
  confluent: ['Confluent', 'confluent.ico'],
  databricks_account: ['Databricks Account', 'databricks.ico'],
  databricks_workspace: ['Databricks Workspace', 'databricks.ico'],
  datadog: ['DataDog', 'datadog.ico'],
  deno: ['Deno Deploy', 'deno.ico'],
  digitalocean: ['Digital Ocean', 'digitalocean.png'],
  entra_id: ['Microsoft Entra ID', 'entra_id.svg'],
  firebase: ['Firebase', 'firebase.png'],
  fivetran: ['Fivetran', 'fivetran.png'],
  github: ['GitHub', 'github.ico'],
  gitlab: ['GitLab', 'gitlab.ico'],
  godaddy: ['GoDaddy', 'godaddy.png'],
  googleadmin: ['Google Admin', 'googleadmin.ico'],
  'googleapis.com': ['Google Cloud Platform', 'google.ico'],
  googleworkspace: ['Google Workspace', 'googleworkspace.ico'],
  homebrew: ['Homebrew', 'homebrew.ico'],
  k8s: ['Kubernetes', 'k8s.png'],
  kafka: ['Kafka', 'kafka.png'],
  lambda: ['Lambda Cloud', 'lambda.svg'],
  linode: ['Linode', 'linode.ico'],
  netlify: ['Netlify', 'netlify.ico'],
  nvidia: ['NVIDIA NGC', 'nvidia.ico'],
  oci: ['Oracle Cloud Infrastructure', 'oci.ico'],
  okta: ['Okta', 'okta.png'],
  openai: ['OpenAI', 'openai.ico'],
  openai_admin: ['OpenAI Admin', 'openai.ico'],
  pagerduty: ['PagerDuty', 'pagerduty.svg'],
  railway: ['Railway', 'railway.ico'],
  snowflake: ['Snowflake', 'snowflake.ico'],
  sumologic: ['SumoLogic', 'sumologic.png'],
  supabase: ['Supabase', 'supabase.ico'],
  typesafe: ['TypeSafe AI', 'typesafe.png'],
  vercel: ['Vercel', 'vercel.ico'],
};

function git(args) {
  return execFileSync('git', ['--no-pager', ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  }).trim();
}

// Accept only the registry's provider -> versions-list YAML schema, not arbitrary YAML.
function parseManifest(text) {
  const providers = new Map();
  let provider;
  let expectingVersions = false;
  let rootSeen = false;
  for (const line of text.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    if (!line.trim()) continue;
    if (line === 'providers:' && !rootSeen) {
      rootSeen = true;
      continue;
    }
    let match = /^  ([a-z0-9_.-]+):$/.exec(line);
    if (rootSeen && match && !expectingVersions) {
      provider = match[1];
      if (providers.has(provider)) throw new Error(`Duplicate provider: ${provider}`);
      providers.set(provider, []);
      expectingVersions = true;
      continue;
    }
    if (provider && expectingVersions && line === '    versions:') {
      expectingVersions = false;
      continue;
    }
    match = /^    (?:  )?- (v\d+\.\d+\.\d+)$/.exec(line);
    if (provider && !expectingVersions && match) {
      providers.get(provider).push(match[1]);
      continue;
    }
    throw new Error(`Unsupported registry manifest line: ${JSON.stringify(line)}`);
  }
  if (!providers.size || expectingVersions) throw new Error('Incomplete registry manifest');
  for (const [name, versions] of providers) {
    if (!versions.length) throw new Error(`No published versions for ${name}`);
  }
  return providers;
}

function compareVersions(left, right) {
  const a = left.slice(1).split('.').map(Number);
  const b = right.slice(1).split('.').map(Number);
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

function utcDate(timestamp) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid Git date: ${timestamp}`);
  return date.toISOString().slice(0, 10);
}

function releaseDates(log) {
  const dates = new Map();
  for (const line of log.split(/\r?\n/)) {
    if (!line) continue;
    const [timestamp, subject] = line.split('\t');
    const match = /^Merge pull request #(\d+) from /.exec(subject)
      || /\(#(\d+)\)\s*$/.exec(subject);
    if (match) {
      const date = utcDate(timestamp);
      const version = `v${date.slice(2, 4)}.${date.slice(5, 7)}.${match[1].padStart(5, '0')}`;
      if (dates.has(version)) throw new Error(`Ambiguous release history for ${version}`);
      dates.set(version, date);
    }
  }
  return dates;
}

function replaceBlock(readme, marker, content) {
  const begin = `<!-- BEGIN ${marker} -->`;
  const end = `<!-- END ${marker} -->`;
  const start = readme.indexOf(begin);
  const finish = readme.indexOf(end);
  if (start < 0 || finish < start || readme.indexOf(begin, start + 1) !== -1
      || readme.indexOf(end, finish + 1) !== -1) {
    throw new Error(`Expected exactly one ${marker} marker pair in README.md`);
  }
  return `${readme.slice(0, start + begin.length)}\n${content}\n${readme.slice(finish)}`;
}

function tableOfContents(readme) {
  let fence;
  const anchors = new Map();
  const entries = [];
  for (const line of readme.split(/\r?\n/)) {
    const delimiter = /^\s*(`{3,}|~{3,})/.exec(line);
    if (delimiter) {
      if (!fence) fence = delimiter[1];
      else if (delimiter[1][0] === fence[0] && delimiter[1].length >= fence.length) fence = undefined;
      continue;
    }
    if (fence) continue;
    const heading = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (!heading) continue;
    const title = heading[2];
    const slug = title.toLowerCase().replace(/[`]/g, '').replace(/[^\w -]/g, '').replace(/ /g, '-');
    const count = anchors.get(slug) || 0;
    anchors.set(slug, count + 1);
    if (heading[1].length === 1 || title === 'Table of Contents') continue;
    const anchor = count ? `${slug}-${count}` : slug;
    entries.push(`${'  '.repeat(heading[1].length - 2)}- [${title}](#${anchor})`);
  }
  return entries.join('\n');
}

function buildCatalog(manifest, dates, firstPublished, root = ROOT) {
  const rows = [
    '| Icon | Provider | Full Name | Latest Version | Date First Published | Date Last Published |',
    '| --- | --- | --- | --- | --- | --- |',
  ];
  const names = [...manifest.keys()].map((name) => name === 'google' ? 'googleapis.com' : name).sort();
  for (const name of names) {
    if (!Object.hasOwn(PROVIDERS, name)) throw new Error(`Add display name and icon metadata for ${name}`);
    const [fullName, icon] = PROVIDERS[name];
    if (!fs.statSync(path.join(root, 'images', icon)).isFile()) {
      throw new Error(`Missing favicon for ${name}: images/${icon}`);
    }
    const registryName = name === 'googleapis.com' ? 'google' : name;
    const latest = [...manifest.get(registryName)].sort(compareVersions).at(-1);
    const last = dates.get(latest);
    if (!last) throw new Error(`No production release commit for ${name} ${latest}; fetch production Git history`);
    const first = firstPublished(name, registryName);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(first) || first > last) {
      throw new Error(`Invalid first publication date for ${name}: ${first}`);
    }
    rows.push(`| <img src="images/${icon}" alt="${fullName}" width="24" height="24"> | \`${name}\` | ${fullName} | \`${latest}\` | ${first} | ${last} |`);
  }
  return rows.join('\n');
}

async function main(args = process.argv.slice(2)) {
  let ref = 'origin/main';
  let check = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--check') check = true;
    else if (args[i] === '--git-ref' && args[i + 1] && !args[i + 1].startsWith('-')) ref = args[++i];
    else throw new Error(`Unknown or incomplete argument: ${args[i]}`);
  }
  if (git(['rev-parse', '--is-shallow-repository']) !== 'false') {
    throw new Error('Full Git history is required; run git fetch --unshallow');
  }
  const commit = git(['rev-parse', '--verify', `${ref}^{commit}`]);
  const dates = releaseDates(git(['log', '--first-parent', '--format=%cI%x09%s', commit]));
  const response = await fetch(MANIFEST_URL, { signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`Registry request failed: HTTP ${response.status}`);
  const manifest = parseManifest(await response.text());
  const catalog = buildCatalog(manifest, dates, (name, registryName) => {
    const history = git([
      'log', '--first-parent', '--reverse', '--format=%cI', commit, '--',
      `providers/src/${name}`, `providers/dist/${name}`, `providers/dist/${registryName}`,
    ]);
    if (!history) throw new Error(`No production history for ${name}`);
    return utcDate(history.split(/\r?\n/)[0]);
  });
  const readmePath = path.join(ROOT, 'README.md');
  const original = fs.readFileSync(readmePath, 'utf8');
  const newline = original.includes('\r\n') ? '\r\n' : '\n';
  let updated = replaceBlock(original.replace(/\r\n/g, '\n'), CATALOG_MARKER, catalog);
  updated = replaceBlock(updated, TOC_MARKER, tableOfContents(updated)).replace(/\n/g, newline);
  if (updated === original) {
    console.log(`Provider catalog is current (${manifest.size} providers).`);
  } else if (check) {
    throw new Error('README.md provider catalog or table of contents is stale; run this script without --check');
  } else {
    fs.writeFileSync(readmePath, updated);
    console.log(`Updated README.md (${manifest.size} providers).`);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`Provider catalog update failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { parseManifest, compareVersions, utcDate, releaseDates, replaceBlock, tableOfContents, buildCatalog };
