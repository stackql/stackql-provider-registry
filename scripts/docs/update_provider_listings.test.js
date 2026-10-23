'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const {
  parseManifest, compareVersions, utcDate, releaseDates, replaceBlock, tableOfContents, buildCatalog,
} = require('./update_provider_listings');

const ROOT = path.resolve(__dirname, '..', '..');

test('parses the registry schema with LF, CRLF and both list indentations', () => {
  const yaml = 'providers:\n  aws:\n    versions:\n    - v26.08.00444\n  google:\n    versions:\n      - v26.08.00446\n';
  const expected = [['aws', ['v26.08.00444']], ['google', ['v26.08.00446']]];
  assert.deepEqual([...parseManifest(yaml)], expected);
  assert.deepEqual([...parseManifest(`\uFEFF${yaml.replace(/\n/g, '\r\n')}`)], expected);
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

test('builds six-column catalog sorted by source directory, with the Google alias and latest release', () => {
  const manifest = new Map([
    ['google', ['v26.08.00446']],
    ['aws', ['v26.08.00444', 'v26.07.00414']],
    ['anthropic_admin', ['v26.07.00416']],
  ]);
  const dates = new Map([
    ['v26.08.00446', '2026-08-20'],
    ['v26.08.00444', '2026-08-20'],
    ['v26.07.00416', '2026-07-09'],
  ]);
  const names = [];
  const catalog = buildCatalog(manifest, dates, (name, registryName) => {
    names.push([name, registryName]);
    return '2024-01-01';
  });
  assert.deepEqual(names, [
    ['anthropic_admin', 'anthropic_admin'], ['aws', 'aws'], ['googleapis.com', 'google'],
  ]);
  assert.match(catalog, /`googleapis\.com` \| Google Cloud Platform \| `v26\.08\.00446`/);
  assert.match(catalog, /`aws` \| Amazon Web Services \| `v26\.08\.00444`/);
  assert.doesNotMatch(catalog, /v26\.07\.00414/);
  for (const row of catalog.split('\n')) assert.equal(row.split('|').length, 8);
});

test('fails explicitly on missing metadata, release history, icons or invalid publication dates', () => {
  const manifest = new Map([['aws', ['v26.08.00444']]]);
  const dates = new Map([['v26.08.00444', '2026-08-20']]);
  assert.throws(() => buildCatalog(new Map([['unknown', ['v26.08.00444']]]), dates, () => '2022-01-01'), /metadata/);
  assert.throws(() => buildCatalog(manifest, new Map(), () => '2022-01-01'), /release commit/);
  assert.throws(() => buildCatalog(manifest, dates, () => '2022-01-01', __dirname), /ENOENT/);
  assert.throws(() => buildCatalog(manifest, dates, () => ''), /first publication date/);
  assert.throws(() => buildCatalog(manifest, dates, () => '2027-01-01'), /first publication date/);
});

test('README lists every current provider directory exactly once, sorted, with six columns and local icons', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const catalog = readme.split('<!-- BEGIN PROVIDER CATALOG -->')[1].split('<!-- END PROVIDER CATALOG -->')[0];
  const rows = catalog.split(/\r?\n/).filter((line) => line.startsWith('| <img'));
  const actual = rows.map((line) => /\| `([^`]+)` \|/.exec(line)[1]);
  const expected = fs.readdirSync(path.join(ROOT, 'providers', 'src'), { withFileTypes: true })
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  assert.deepEqual(actual, expected);
  for (const row of rows) {
    assert.equal(row.split('|').length, 8);
    const icon = /src="([^"]+)"/.exec(row)[1];
    assert.ok(fs.statSync(path.join(ROOT, ...icon.split('/'))).isFile());
    assert.match(row, /\| `v\d+\.\d+\.\d+` \| \d{4}-\d{2}-\d{2} \| \d{4}-\d{2}-\d{2} \|$/);
  }
  const toc = readme.split('<!-- BEGIN TABLE OF CONTENTS -->')[1].split('<!-- END TABLE OF CONTENTS -->')[0].trim();
  assert.equal(toc, tableOfContents(readme));
  assert.equal(replaceBlock(readme, 'PROVIDER CATALOG', catalog.trim()), readme);
});
