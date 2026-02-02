set -e

# Create directories (Fix A: separate public vs private)
mkdir -p app/public/lib app/private/data app/private/db app/private/storage

# docker-compose.yml (Fix A volumes)
cat > docker-compose.yml <<'YAML'
services:
  web:
    build: .
    ports:
      - "8080:80"
    volumes:
      - ./app/public:/var/www/html
      - ./app/private:/var/www/private
    environment:
      - APP_ENV=dev
      - API_ALLOWLIST=api.github.com
YAML

# Dockerfile
cat > Dockerfile <<'DOCKER'
FROM php:8.3-apache

RUN a2enmod rewrite headers

# SQLite support
RUN apt-get update && apt-get install -y \
    libsqlite3-dev \
    && docker-php-ext-install pdo_sqlite \
    && rm -rf /var/lib/apt/lists/*

COPY apache-vhost.conf /etc/apache2/sites-available/000-default.conf

WORKDIR /var/www/html
DOCKER

# Apache virtual host (CSP fixed)
cat > apache-vhost.conf <<'APACHE'
<VirtualHost *:80>
    DocumentRoot /var/www/html

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "no-referrer"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

    Header always set Content-Security-Policy "expr=default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'self'; form-action 'self'"

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
APACHE

# security.php (Fix A: point to /var/www/private)
cat > app/public/lib/security.php <<'PHP'
<?php

function h(string $s): string {
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Private base path is outside the web root.
 * In the container:
 *  - public:  /var/www/html
 *  - private: /var/www/private
 */
function private_base(): string {
  return '/var/www/private';
}

function ensure_private_dirs(): void {
  $base = private_base();
  foreach (['db', 'storage', 'data'] as $d) {
    $path = $base . '/' . $d;
    if (!is_dir($path)) { @mkdir($path, 0700, true); }
  }
}

function db(): PDO {
  ensure_private_dirs();
  $dbPath = private_base() . '/db/app.sqlite';
  return new PDO('sqlite:' . $dbPath, null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
  ]);
}

function csrf_start(): void {
  if (session_status() !== PHP_SESSION_ACTIVE) session_start();
  if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
  }
}

function csrf_token(): string {
  csrf_start();
  return $_SESSION['csrf'];
}

function csrf_verify(): void {
  csrf_start();
  $token = $_POST['csrf'] ?? '';
  if (!is_string($token) || !hash_equals($_SESSION['csrf'], $token)) {
    http_response_code(403);
    exit('CSRF verification failed');
  }
}

function client_ip(): string {
  return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function rate_limit(string $key, int $max, int $window): void {
  ensure_private_dirs();
  $bucket = hash('sha256', $key . '|' . client_ip());
  $file = private_base() . '/storage/rl_' . $bucket . '.json';

  $now = time();
  $data = ['reset' => $now + $window, 'count' => 0];

  if (is_file($file)) {
    $raw = file_get_contents($file);
    $tmp = json_decode($raw ?: '', true);
    if (is_array($tmp) && isset($tmp['reset'], $tmp['count'])) {
      $data = $tmp;
      if ($now > (int)$data['reset']) {
        $data = ['reset' => $now + $window, 'count' => 0];
      }
    }
  }

  $data['count'] = ((int)$data['count']) + 1;
  file_put_contents($file, json_encode($data), LOCK_EX);

  if ($data['count'] > $max) {
    http_response_code(429);
    exit('Too many requests');
  }
}

function safe_fetch_json(string $url): array {
  $allow = array_filter(array_map('trim', explode(',', getenv('API_ALLOWLIST') ?: '')));
  $host = parse_url($url, PHP_URL_HOST);

  if (!$host || !in_array($host, $allow, true)) {
    throw new RuntimeException('Blocked by API allowlist');
  }

  $ctx = stream_context_create([
    'http' => [
      'timeout' => 3,
      'follow_location' => 0,
      'header' => "Accept: application/json\r\nUser-Agent: secure-feedback-demo\r\n",
    ],
    'ssl' => [
      'verify_peer' => true,
      'verify_peer_name' => true,
    ],
  ]);

  $raw = @file_get_contents($url, false, $ctx);
  if ($raw === false) throw new RuntimeException('API request failed');

  $data = json_decode($raw, true);
  return is_array($data) ? $data : [];
}

function csv_safe_cell(string $v): string {
  return preg_match('/^[=+\-@]/', ltrim($v)) ? "'" . $v : $v;
}

/** Read context tags from private data folder */
function load_context_tags(): array {
  ensure_private_dirs();
  $base = private_base();
  $tags = [];

  $jsonPath = $base . '/data/context.json';
  if (is_file($jsonPath)) {
    $raw = file_get_contents($jsonPath);
    $data = json_decode($raw ?: '', true);
    if (is_array($data) && isset($data['tags']) && is_array($data['tags'])) {
      foreach ($data['tags'] as $t) {
        if (is_string($t) && strlen($t) <= 30) $tags[] = $t;
      }
    }
  }

  $csvPath = $base . '/data/context.csv';
  if (is_file($csvPath)) {
    $fh = fopen($csvPath, 'r');
    if ($fh) {
      $lineCount = 0;
      while (($row = fgetcsv($fh)) !== false) {
        $lineCount++;
        if ($lineCount > 200) break;
        $t = $row[0] ?? '';
        if (is_string($t)) {
          $t = trim($t);
          if ($t !== '' && strlen($t) <= 30) $tags[] = $t;
        }
      }
      fclose($fh);
    }
  }

  $tags = array_values(array_unique($tags));
  sort($tags);
  return $tags;
}
PHP

# index.php (uses CSS; now also shows derived tags from private context)
cat > app/public/index.php <<'PHP'
<?php
require_once __DIR__ . '/lib/security.php';

csrf_start();
$pdo = db();

$pdo->exec("
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  name TEXT NOT NULL,
  comment TEXT NOT NULL
);
");

$errors = [];
$contextTags = load_context_tags();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  rate_limit('comment', 30, 60);
  csrf_verify();

  $name = trim((string)($_POST['name'] ?? ''));
  $comment = trim((string)($_POST['comment'] ?? ''));

  if ($name === '' || strlen($name) > 50) $errors[] = 'Name is required (max 50 chars).';
  if ($comment === '' || strlen($comment) > 800) $errors[] = 'Comment is required (max 800 chars).';

  if (!$errors) {
    $stmt = $pdo->prepare("INSERT INTO comments (created_at, name, comment) VALUES (?, ?, ?)");
    $stmt->execute([gmdate('c'), $name, $comment]);
    header('Location: /');
    exit;
  }
}

$rows = $pdo->query("SELECT * FROM comments ORDER BY id DESC")->fetchAll();

function derive_tags(string $comment, array $tags): array {
  $found = [];
  $lc = mb_strtolower($comment, 'UTF-8');
  foreach ($tags as $t) {
    if (mb_stripos($lc, mb_strtolower($t, 'UTF-8'), 0, 'UTF-8') !== false) {
      $found[] = $t;
    }
  }
  return $found;
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Secure Feedback Demo</title>
  <style>
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background: #f6f7fb;
      color: #111827;
      line-height: 1.5;
    }
    .wrap { max-width: 980px; margin: 0 auto; padding: 28px 16px 48px; }
    .header { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; margin-bottom: 18px; flex-wrap: wrap; }
    h1 { margin: 0; font-size: 28px; letter-spacing: -0.02em; }
    .sub { margin: 6px 0 0; color: #4b5563; font-size: 14px; }
    .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 14px; box-shadow: 0 1px 2px rgba(0,0,0,0.03); padding: 16px; }
    label { display: block; font-size: 13px; color: #374151; margin: 0 0 6px; }
    input, textarea { width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 10px; font: inherit; background: #fff; outline: none; }
    input:focus, textarea:focus { border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99,102,241,0.18); }
    textarea { min-height: 110px; resize: vertical; }
    .row { display: grid; grid-template-columns: 1fr; gap: 12px; }
    @media (min-width: 720px) { .row { grid-template-columns: 240px 1fr; } }
    .actions { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-top: 6px; }
    button { border: 0; background: #111827; color: #fff; padding: 10px 14px; border-radius: 10px; font-weight: 600; cursor: pointer; }
    button:hover { filter: brightness(1.05); }
    a { color: #4f46e5; text-decoration: none; font-weight: 600; }
    a:hover { text-decoration: underline; }
    .errors { border: 1px solid #fecaca; background: #fff1f2; color: #991b1b; border-radius: 12px; padding: 12px 14px; margin-bottom: 14px; font-size: 14px; }
    .list { margin-top: 18px; display: grid; gap: 12px; }
    .item { background: #fff; border: 1px solid #e5e7eb; border-radius: 14px; padding: 14px 16px; }
    .meta { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; color: #6b7280; font-size: 13px; margin-bottom: 6px; }
    .name { color: #111827; font-weight: 700; }
    .comment { margin: 0; white-space: pre-wrap; word-wrap: break-word; }
    .tagline { margin-top: 10px; display: flex; flex-wrap: wrap; gap: 8px; }
    .tag { font-size: 12px; border: 1px solid #e5e7eb; background: #f9fafb; border-radius: 999px; padding: 2px 10px; color: #374151; }
    .muted { color: #6b7280; font-size: 13px; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; font-size: 12px; background: #f3f4f6; padding: 2px 6px; border-radius: 8px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div>
        <h1>Secure Feedback Demo</h1>
        <p class="sub">Public web root is <code>/var/www/html</code>. Private data is stored at <code>/var/www/private</code>.</p>
      </div>
      <div><a href="/export.php">Export CSV</a></div>
    </div>

    <div class="card">
      <?php if ($errors): ?>
        <div class="errors">
          <b>Please fix the following:</b>
          <ul>
            <?php foreach ($errors as $e): ?><li><?= h($e) ?></li><?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>

      <form method="post" action="/">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <div class="row">
          <div>
            <label for="name">Name</label>
            <input id="name" name="name" maxlength="50" placeholder="Your name" required>
          </div>
          <div>
            <label for="comment">Comment</label>
            <textarea id="comment" name="comment" maxlength="800" placeholder="Write your feedback..." required></textarea>
          </div>
        </div>
        <div class="actions">
          <div class="muted">Max length: <code>50</code> for name, <code>800</code> for comment.</div>
          <button type="submit">Submit</button>
        </div>
      </form>

      <?php if ($contextTags): ?>
        <div class="tagline" aria-label="Context tags loaded from private data">
          <?php foreach ($contextTags as $t): ?><span class="tag"><?= h($t) ?></span><?php endforeach; ?>
        </div>
      <?php endif; ?>
    </div>

    <div class="list">
      <?php if (!$rows): ?>
        <div class="item">No comments yet. Add the first one.</div>
      <?php endif; ?>

      <?php foreach ($rows as $r): ?>
        <?php $tags = derive_tags((string)$r['comment'], $contextTags); ?>
        <div class="item">
          <div class="meta">
            <span class="name"><?= h($r['name']) ?></span>
            <span><?= h($r['created_at']) ?></span>
          </div>
          <p class="comment"><?= h($r['comment']) ?></p>
          <?php if ($tags): ?>
            <div class="tagline">
              <?php foreach ($tags as $t): ?><span class="tag"><?= h($t) ?></span><?php endforeach; ?>
            </div>
          <?php endif; ?>
        </div>
      <?php endforeach; ?>
    </div>
  </div>
</body>
</html>
PHP

# export.php (reads DB from private path via db())
cat > app/public/export.php <<'PHP'
<?php
require_once __DIR__ . '/lib/security.php';

$pdo = db();
$pdo->exec("
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  name TEXT NOT NULL,
  comment TEXT NOT NULL
);
");

$rows = $pdo->query("SELECT id, created_at, name, comment FROM comments ORDER BY id DESC")->fetchAll();

header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="comments.csv"');

$out = fopen('php://output', 'w');
fputcsv($out, ['id','created_at','name','comment']);

foreach ($rows as $r) {
  fputcsv($out, [
    (int)$r['id'],
    $r['created_at'],
    csv_safe_cell((string)$r['name']),
    csv_safe_cell((string)$r['comment'])
  ]);
}
fclose($out);
PHP

# context files now go to PRIVATE data folder (Fix A)
cat > app/private/data/context.json <<'JSON'
{"tags":["slow","rude","clean","overpriced","friendly","late"]}
JSON

cat > app/private/data/context.csv <<'CSV'
noisy
crowded
great service
refund
CSV

# Start containers
docker compose up -d --build
echo "App is running. Open port 8080 from the Ports tab."
