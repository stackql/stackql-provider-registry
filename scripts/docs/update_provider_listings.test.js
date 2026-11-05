'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const {
  parseManifest, compareVersions, utcDate, releaseDates, iconIndex, resolveIcon, providerId,
  sourceDirectories, replaceBlock, tableOfContents, buildCatalog,
} = require('./update_provider_listings');

const ROOT = path.resolve(__dirname, '..', '..');

function withTempDir(name, callback) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `${name}-`));
  try {
    return callback(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('parses the registry schema with LF, CRLF and both list indentations', () => {
  const yaml = 'providers:\n  aws:\n    versions:\n    - v26.08.00444\n  google:\n    versions:\n      - v26.08.00446\n';
  const expected = [['aws', ['v26.08.00444']], ['google', ['v26.08.00446']]];
  assert.deepEqual([...parseManifest(yaml)], expected);
  assert.deepEqual([...parseManifest(`﻿${yaml.replace(/\n/g, '\r\n')}`)], expected);
});

test('rejects incomplete, duplicate and unsupported manifest data', () => {
  for (const yaml of [
    '', 'providers:', 'providers:\n  aws:',
    'providers:\n  aws:\n    versions:',
    'providers:\n  aws:\n    versions:\n    - invalid',
    'providers:\n  aws:\n    versions:\n    - v26.08.00444\n  aws:',
    'providers:\n  aws:\n    versions:\n    - v26.08.00444\nunexpected: true',
  ]) {
    assert.throws(() => parseManifest(yaml));
  }
});

test('selects versions numerically rather than lexicographically or by list order', () => {
  assert.deepEqual(
    ['v9.12.99999', 'v26.9.00461', 'v26.10.00481', 'v26.09.00459'].sort(compareVersions),
    ['v9.12.99999', 'v26.09.00459', 'v26.9.00461', 'v26.10.00481'],
  );
});

test('derives UTC release dates from merge and squash commits, ignoring source commits', () => {
  const dates = releaseDates([
    '2026-10-21T16:15:29+11:00\tMerge pull request #481 from stackql/dev',
    '2026-07-01T00:15:00+10:00\tProvider update (#405)',
    '2026-10-19T17:22:55+11:00\tlambda provider',
  ].join('\n'));
  assert.deepEqual([...dates], [['v26.10.00481', '2026-10-21'], ['v26.06.00405', '2026-06-30']]);
  assert.equal(utcDate('2022-08-20T00:15:24+10:00'), '2022-08-19');
  assert.throws(() => utcDate('not a date'), /Invalid Git date/);
  assert.throws(() => releaseDates([
    '2026-10-21T05:15:29Z\tMerge pull request #481 from stackql/dev',
    '2026-10-22T05:15:29Z\tAnother release (#481)',
  ].join('\n')), /Ambiguous release history/);
});

test('resolves icons by exact stem, then longest prefix, and leaves unmatched providers blank', () => {
  withTempDir('icons', (dir) => {
    for (const file of ['aws.png', 'aws.ico', 'databricks.ico', 'google.ico', 'googleadmin.ico', 'entra_id.svg']) {
      fs.writeFileSync(path.join(dir, file), '');
    }
    fs.mkdirSync(path.join(dir, 'ignored.ico'));
    const icons = iconIndex(dir);
    assert.deepEqual([...icons], [
      ['aws', 'aws.ico'], ['databricks', 'databricks.ico'], ['entra_id', 'entra_id.svg'],
      ['google', 'google.ico'], ['googleadmin', 'googleadmin.ico'],
    ]);
    assert.equal(resolveIcon('aws', icons), 'aws.ico');
    assert.equal(resolveIcon('awscc', icons), 'aws.ico');
    assert.equal(resolveIcon('databricks_account', icons), 'databricks.ico');
    assert.equal(resolveIcon('databricks_workspace', icons), 'databricks.ico');
    assert.equal(resolveIcon('googleadmin', icons), 'googleadmin.ico');
    assert.equal(resolveIcon('googleworkspace', icons), 'google.ico');
    assert.equal(resolveIcon('entra_id', icons), 'entra_id.svg');
    assert.equal(resolveIcon('k8s', icons), undefined);
    assert.equal(resolveIcon('ignored', icons), undefined);
  });
});

test('maps registry ids to source directories from the top-level provider document id', () => {
  assert.equal(providerId('config:\n  auth:\n    id: nested\nid: google\nname: google\n'), 'google');
  assert.equal(providerId('id: "quoted"\r\nname: quoted\r\n'), 'quoted');
  assert.equal(providerId('  id: nested\nname: only\n'), undefined);
  withTempDir('sources', (dir) => {
    const write = (provider, version, body) => {
      fs.mkdirSync(path.join(dir, provider, version), { recursive: true });
      fs.writeFileSync(path.join(dir, provider, version, 'provider.yaml'), body);
    };
    write('googleapis.com', 'v00.00.00000', 'config:\n  auth:\n    id: nested\nid: google\nname: google\n');
    write('aws', 'v00.00.00000', 'id: aws\nname: aws\n');
    fs.mkdirSync(path.join(dir, 'nodoc', 'v00.00.00000'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'README.md'), '');
    assert.deepEqual([...sourceDirectories(dir)].sort(), [
      ['aws', 'aws'], ['google', 'googleapis.com'], ['nodoc', 'nodoc'],
    ]);
    write('google', 'v00.00.00000', 'id: google\n');
    assert.throws(() => sourceDirectories(dir), /multiple source directories/);
  });
});

test('replaces only generated blocks and rejects missing, reversed or duplicate markers', () => {
  const readme = 'before\n<!-- BEGIN TEST -->\nold\n<!-- END TEST -->\nafter\n';
  assert.equal(
    replaceBlock(readme, 'TEST', 'new'),
    'before\n<!-- BEGIN TEST -->\nnew\n<!-- END TEST -->\nafter\n',
  );
  for (const invalid of [
    '', '<!-- END TEST --><!-- BEGIN TEST -->',
    `${readme}<!-- BEGIN TEST -->`, `${readme}<!-- END TEST -->`,
  ]) {
    assert.throws(() => replaceBlock(invalid, 'TEST', 'new'), /marker pair/);
  }
});

test('generates nested TOC links, ignoring fenced code and handling duplicate headings', () => {
  assert.equal(tableOfContents([
    '# Project', '## Table of Contents', '## Provider Catalog', '### Updating the Catalog',
    '```bash', '## Not a heading', '```', '~~~', '## Also code', '~~~',
    '## Testing using the `dev` Registry', '## Provider Catalog',
  ].join('\n')), [
    '- [Provider Catalog](#provider-catalog)',
    '  - [Updating the Catalog](#updating-the-catalog)',
    '- [Testing using the `dev` Registry](#testing-using-the-dev-registry)',
    '- [Provider Catalog](#provider-catalog-1)',
  ].join('\n'));
});

test('builds five-column catalog sorted by registry name with resolved or blank icons and latest release', () => {
  const manifest = new Map([
    ['google', ['v26.08.00446']],
    ['aws', ['v26.08.00444', 'v26.07.00414']],
    ['anthropic_admin', ['v26.07.00416']],
    ['newprovider', ['v26.07.00416']],
  ]);
  const dates = new Map([
    ['v26.08.00446', '2026-08-20'],
    ['v26.08.00444', '2026-08-20'],
    ['v26.07.00416', '2026-07-09'],
  ]);
  const icons = new Map([['anthropic', 'anthropic.png'], ['aws', 'aws.ico'], ['google', 'google.ico']]);
  const names = [];
  const catalog = buildCatalog(manifest, dates, (name) => {
    names.push(name);
    return '2024-01-01';
  }, icons);
  assert.deepEqual(names, ['anthropic_admin', 'aws', 'google', 'newprovider']);
  const rows = catalog.split('\n');
  assert.equal(rows[0], '| Icon | Provider | Latest Version | Date First Published | Date Last Published |');
  assert.equal(rows[2], '| <img src="images/anthropic.png" alt="anthropic_admin" width="24" height="24"> | `anthropic_admin` | `v26.07.00416` | 2024-01-01 | 2026-07-09 |');
  assert.match(catalog, /images\/google\.ico" alt="google" [^|]*\| `google` \| `v26\.08\.00446`/);
  assert.match(catalog, /images\/aws\.ico" alt="aws" [^|]*\| `aws` \| `v26\.08\.00444`/);
  assert.match(catalog, /\n\|  \| `newprovider` \| `v26\.07\.00416` \| 2024-01-01 \| 2026-07-09 \|/);
  assert.doesNotMatch(catalog, /v26\.07\.00414/);
  for (const row of rows) assert.equal(row.split('|').length, 7);
});

test('fails explicitly on missing release history or invalid publication dates', () => {
  const manifest = new Map([['aws', ['v26.08.00444']]]);
  const dates = new Map([['v26.08.00444', '2026-08-20']]);
  assert.throws(() => buildCatalog(manifest, new Map(), () => '2022-01-01', new Map()), /release commit/);
  assert.throws(() => buildCatalog(manifest, dates, () => '', new Map()), /first publication date/);
  assert.throws(() => buildCatalog(manifest, dates, () => '2027-01-01', new Map()), /first publication date/);
});

test('README lists every current provider id exactly once, sorted, with five columns and repository icons', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const catalog = readme.split('<!-- BEGIN PROVIDER CATALOG -->')[1].split('<!-- END PROVIDER CATALOG -->')[0];
  const rows = catalog.split(/\r?\n/).filter((line) => line.startsWith('| ')).slice(2);
  const actual = rows.map((line) => /\| `([^`]+)` \|/.exec(line)[1]);
  assert.deepEqual(actual, [...sourceDirectories().keys()].sort());
  const icons = iconIndex();
  for (const [index, row] of rows.entries()) {
    assert.equal(row.split('|').length, 7);
    const expected = resolveIcon(actual[index], icons);
    const cell = row.split('|')[1].trim();
    if (expected) {
      assert.equal(cell, `<img src="images/${expected}" alt="${actual[index]}" width="24" height="24">`);
      assert.ok(fs.statSync(path.join(ROOT, 'images', expected)).isFile());
    } else {
      assert.equal(cell, '');
    }
    assert.match(row, /\| `v\d+\.\d+\.\d+` \| \d{4}-\d{2}-\d{2} \| \d{4}-\d{2}-\d{2} \|$/);
  }
  const toc = readme.split('<!-- BEGIN TABLE OF CONTENTS -->')[1].split('<!-- END TABLE OF CONTENTS -->')[0].trim();
  assert.equal(toc, tableOfContents(readme));
  assert.equal(replaceBlock(readme, 'PROVIDER CATALOG', catalog.trim()), readme);
});
