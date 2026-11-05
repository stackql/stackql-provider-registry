#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const IMAGES_DIR = path.join(ROOT, 'images');
const SOURCE_DIR = path.join(ROOT, 'providers', 'src');
const MANIFEST_URL = 'https://registry.stackql.app/providers/dist/providers.yaml';
const TOC_MARKER = 'TABLE OF CONTENTS';
const CATALOG_MARKER = 'PROVIDER CATALOG';

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
  for (const line of text.replace(/^﻿/, '').split(/\r?\n/)) {
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

// Index icon files by stem (file name without extension); the first file in sorted order wins per stem.
function iconIndex(dir = IMAGES_DIR) {
  const icons = new Map();
  for (const file of fs.readdirSync(dir).sort()) {
    if (!fs.statSync(path.join(dir, file)).isFile()) continue;
    const stem = path.parse(file).name;
    if (!icons.has(stem)) icons.set(stem, file);
  }
  return icons;
}

// Exact stem match first, otherwise the longest stem the provider name starts with,
// so databricks.ico serves databricks_account and databricks_workspace. Undefined when nothing matches.
function resolveIcon(name, icons) {
  let best;
  for (const stem of icons.keys()) {
    if (name.startsWith(stem) && (!best || stem.length > best.length)) best = stem;
  }
  return best === undefined ? undefined : icons.get(best);
}

// Top-level id from a provider document; nested ids are indented and never match.
function providerId(document) {
  const match = /^id:[ \t]*["']?([A-Za-z0-9_.-]+)["']?[ \t]*\r?$/m.exec(document);
  return match ? match[1] : undefined;
}

// Map registry provider ids to providers/src directories (googleapis.com publishes as google).
function sourceDirectories(dir = SOURCE_DIR) {
  const sources = new Map();
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    let id;
    for (const version of fs.readdirSync(path.join(dir, entry.name)).sort()) {
      const file = path.join(dir, entry.name, version, 'provider.yaml');
      if (!fs.existsSync(file)) continue;
      id = providerId(fs.readFileSync(file, 'utf8'));
      if (id) break;
    }
    id = id || entry.name;
    if (sources.has(id)) {
      throw new Error(`Provider ${id} has multiple source directories: ${sources.get(id)}, ${entry.name}`);
    }
    sources.set(id, entry.name);
  }
  return sources;
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

function buildCatalog(manifest, dates, firstPublished, icons) {
  const rows = [
    '| Icon | Provider | Latest Version | Date First Published | Date Last Published |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const name of [...manifest.keys()].sort()) {
    const icon = resolveIcon(name, icons);
    const image = icon ? `<img src="images/${icon}" alt="${name}" width="24" height="24">` : '';
    const latest = [...manifest.get(name)].sort(compareVersions).at(-1);
    const last = dates.get(latest);
    if (!last) throw new Error(`No production release commit for ${name} ${latest}; fetch production Git history`);
    const first = firstPublished(name);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(first) || first > last) {
      throw new Error(`Invalid first publication date for ${name}: ${first}`);
    }
    rows.push(`| ${image} | \`${name}\` | \`${latest}\` | ${first} | ${last} |`);
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
  const icons = iconIndex();
  const sources = sourceDirectories();
  const response = await fetch(MANIFEST_URL, { signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`Registry request failed: HTTP ${response.status}`);
  const manifest = parseManifest(await response.text());
  const catalog = buildCatalog(manifest, dates, (name) => {
    const source = sources.get(name) || name;
    const history = git([
      'log', '--first-parent', '--reverse', '--format=%cI', commit, '--',
      `providers/src/${source}`, `providers/dist/${source}`, `providers/dist/${name}`,
    ]);
    if (!history) throw new Error(`No production history for ${name}`);
    return utcDate(history.split(/\r?\n/)[0]);
  }, icons);
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

module.exports = {
  parseManifest, compareVersions, utcDate, releaseDates, iconIndex, resolveIcon, providerId,
  sourceDirectories, replaceBlock, tableOfContents, buildCatalog,
};
