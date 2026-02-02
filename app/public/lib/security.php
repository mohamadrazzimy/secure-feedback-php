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
