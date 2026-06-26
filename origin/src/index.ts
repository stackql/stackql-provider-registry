/**
 * StackQL Provider Registry origin - Cloudflare Worker (green).
 *
 * Port of the Deno Deploy origin (deno-deploy-registry/website/index.ts).
 * The URL contract is preserved exactly:
 *
 *   GET (anything).tgz           -> 200 application/gzip, log one download event
 *   GET (anything)providers.yaml -> 200 text/plain, not logged
 *   GET (anything)/ping          -> 202 "pong"
 *   GET /analytics        -> 200 text/html dashboard (24h / 7d / 30d + 12-month matrix)
 *   GET /analytics/last24hours -> 200 application/json
 *   any other path        -> 404
 *   any non-GET method    -> 405
 *
 * Provider docs are served from R2 (binding REGISTRY_BUCKET). Download analytics
 * are written one row per .tgz pull to D1 (binding ANALYTICS_DB) inside
 * ctx.waitUntil so logging never adds latency to a pull.
 */

export interface Env {
  REGISTRY_BUCKET: R2Bucket;
  ANALYTICS_DB: D1Database;
}

interface RequestMetadata {
  ipAddr: string;
  ts: string;
  userAgent: string;
  host: string;
}

function extractRequestMetadata(request: Request): RequestMetadata {
  return {
    // Deno used conn.remoteAddr.hostname; on Cloudflare the real client IP is here.
    ipAddr: request.headers.get('CF-Connecting-IP') || '',
    ts: new Date().toISOString(),
    userAgent: request.headers.get('user-agent') || '',
    host: request.headers.get('host') || '',
  };
}

interface DownloadRow {
  ts: string;
  provider: string;
  version: string;
  pathname: string;
  host: string;
  ipAddr: string;
  userAgent: string;
}

function constructDownloadRow(pathname: string, meta: RequestMetadata): DownloadRow {
  // mirrors constructKvEntry: provider/version are parsed off /providers/dist/<provider>/<version>.tgz
  const document = pathname.replace('/providers/dist/', '');
  const provider = document.split('/')[0];
  const version = document.split('/')[1] || '';

  return {
    ts: meta.ts,
    provider,
    version,
    pathname,
    host: meta.host,
    ipAddr: meta.ipAddr,
    userAgent: meta.userAgent,
  };
}

async function logDownload(env: Env, row: DownloadRow): Promise<void> {
  try {
    await env.ANALYTICS_DB.prepare(
      `INSERT INTO downloads (ts, provider, version, pathname, host, ip_addr, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(row.ts, row.provider, row.version, row.pathname, row.host, row.ipAddr, row.userAgent)
      .run();
  } catch (err) {
    console.error(`Error logging download to D1: ${err}`);
  }
}

async function getProviderDownloads(env: Env, days: number): Promise<Map<string, number>> {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const { results } = await env.ANALYTICS_DB.prepare(
    `SELECT provider, COUNT(*) AS cnt FROM downloads WHERE ts >= ? GROUP BY provider`,
  )
    .bind(cutoff)
    .all<{ provider: string; cnt: number }>();

  const providers = new Map<string, number>();
  for (const row of results ?? []) {
    providers.set(row.provider, row.cnt);
  }
  return providers;
}

async function getYearlyMatrix(env: Env): Promise<{
  providers: string[];
  months: string[];
  data: Record<string, Record<string, number>>;
}> {
  // last 12 months, grouped by provider and YYYY-MM
  const start = new Date();
  start.setMonth(start.getMonth() - 11);
  const startStr = start.toISOString();

  const { results } = await env.ANALYTICS_DB.prepare(
    `SELECT provider, substr(ts, 1, 7) AS month, COUNT(*) AS cnt
       FROM downloads
      WHERE ts >= ?
      GROUP BY provider, month`,
  )
    .bind(startStr)
    .all<{ provider: string; month: string; cnt: number }>();

  const providerCounts: Record<string, Record<string, number>> = {};
  const providers = new Set<string>();
  const months = new Set<string>();

  for (const row of results ?? []) {
    providers.add(row.provider);
    months.add(row.month);
    if (!providerCounts[row.provider]) {
      providerCounts[row.provider] = {};
    }
    providerCounts[row.provider][row.month] = row.cnt;
  }

  return {
    providers: Array.from(providers).sort(),
    months: Array.from(months).sort(),
    data: providerCounts,
  };
}

async function handleAnalytics(env: Env, pathname: string): Promise<Response> {
  try {
    if (pathname === '/analytics/last24hours') {
      try {
        const last24h = await getProviderDownloads(env, 1);
        return new Response(JSON.stringify(Object.fromEntries(last24h), null, 2), {
          headers: {
            'content-type': 'application/json',
          },
        });
      } catch (error: any) {
        return new Response(`Error getting 24h stats: ${error.message}`, { status: 500 });
      }
    }

    const [last24h, last7d, last30d, yearlyMatrix] = await Promise.all([
      getProviderDownloads(env, 1),
      getProviderDownloads(env, 7),
      getProviderDownloads(env, 30),
      getYearlyMatrix(env),
    ]);

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StackQL Registry Analytics</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .table-container {
            overflow-x: auto;
            margin-bottom: 2rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1rem;
            background: white;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background: #f5f5f5;
        }
        h2 {
            color: #333;
            margin-top: 2rem;
        }
        @media (max-width: 768px) {
            th, td {
                padding: 8px;
            }
        }
        .matrix-container {
            overflow-x: auto;
        }
        .highlight {
            background-color: #f0f8ff;
        }
    </style>
</head>
<body>
    <h1>StackQL Registry Analytics</h1>

    <h2>Downloads by Provider (Last 24 Hours)</h2>
    <div class="table-container">
        <table>
            <tr>
                <th>Provider</th>
                <th>Downloads</th>
            </tr>
            ${Array.from(last24h.entries())
              .sort(([, a], [, b]) => b - a)
              .map(
                ([provider, count]) => `
                    <tr>
                        <td>${provider}</td>
                        <td>${count}</td>
                    </tr>
                `,
              )
              .join('')}
        </table>
    </div>

    <h2>Downloads by Provider (Last 7 Days)</h2>
    <div class="table-container">
        <table>
            <tr>
                <th>Provider</th>
                <th>Downloads</th>
            </tr>
            ${Array.from(last7d.entries())
              .sort(([, a], [, b]) => b - a)
              .map(
                ([provider, count]) => `
                    <tr>
                        <td>${provider}</td>
                        <td>${count}</td>
                    </tr>
                `,
              )
              .join('')}
        </table>
    </div>

    <h2>Downloads by Provider (Last 30 Days)</h2>
    <div class="table-container">
        <table>
            <tr>
                <th>Provider</th>
                <th>Downloads</th>
            </tr>
            ${Array.from(last30d.entries())
              .sort(([, a], [, b]) => b - a)
              .map(
                ([provider, count]) => `
                    <tr>
                        <td>${provider}</td>
                        <td>${count}</td>
                    </tr>
                `,
              )
              .join('')}
        </table>
    </div>

    <h2>Provider Downloads by Month (Last 12 Months)</h2>
    <div class="matrix-container">
        <table>
            <tr>
                <th>Provider</th>
                ${yearlyMatrix.months
                  .map(
                    (month) => `
                    <th>${month}</th>
                `,
                  )
                  .join('')}
            </tr>
            ${yearlyMatrix.providers
              .map(
                (provider) => `
                <tr>
                    <td>${provider}</td>
                    ${yearlyMatrix.months
                      .map(
                        (month) => `
                        <td>${yearlyMatrix.data[provider]?.[month] || 0}</td>
                    `,
                      )
                      .join('')}
                </tr>
            `,
              )
              .join('')}
        </table>
    </div>
</body>
</html>`;

    return new Response(html, {
      headers: {
        'content-type': 'text/html',
      },
    });
  } catch (error: any) {
    return new Response(`Error generating analytics: ${error.message}`, { status: 500 });
  }
}

async function handleRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const { pathname, href } = new URL(request.url);

  let isProviderListReq = false;

  console.info(`request: ${request.method} ${href}`);

  let contentType: string;

  // do not accept any other method than GET
  if (request.method !== 'GET') {
    return new Response(null, {
      status: 405,
      statusText: 'Method Not Allowed',
    });
  }

  // route to analytics
  if (pathname.startsWith('/analytics')) {
    return await handleAnalytics(env, pathname);
  }

  // route to ping
  if (pathname.endsWith('ping')) {
    return new Response('pong', {
      status: 202,
      statusText: 'OK',
    });
  }

  // is a provider download or listing request?
  let cacheControl: string;
  if (pathname.endsWith('tgz')) {
    contentType = 'application/gzip';
    // version-pinned artifacts are immutable; keep repeat pulls off R2
    cacheControl = 'public, max-age=31536000, immutable';
  } else if (pathname.endsWith('providers.yaml')) {
    isProviderListReq = true;
    contentType = 'text/plain';
    // providers.yaml changes on every publish; short cache only
    cacheControl = 'public, max-age=60';
  } else {
    return new Response(null, {
      status: 404,
      statusText: 'Not Found',
    });
  }

  // R2 key mirrors the Deno on-disk layout: `.${pathname}` -> strip the leading slash
  const key = pathname.replace(/^\//, '');

  const obj = await env.REGISTRY_BUCKET.get(key);
  if (obj === null) {
    return new Response(null, {
      status: 404,
      statusText: 'Not Found',
    });
  }

  // get request metadata and log the download (not provider list, not localhost)
  const metadata = extractRequestMetadata(request);
  if (!metadata.host.startsWith('localhost')) {
    if (!isProviderListReq) {
      const row = constructDownloadRow(pathname, metadata);
      // never add latency to the pull
      ctx.waitUntil(logDownload(env, row));
    }
  } else {
    console.info('skipping analytics insert for localhost');
  }

  return new Response(obj.body, {
    status: 200,
    statusText: 'OK',
    headers: {
      'content-type': contentType,
      'cache-control': cacheControl,
    },
  });
}

export default {
  fetch: handleRequest,
};
