<?php

function h(string $s): string {
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function ensure_dirs(): void {
  foreach (['db', 'storage'] as $d) {
    $path = __DIR__ . '/../' . $d;
    if (!is_dir($path)) { mkdir($path, 0700, true); }
  }
}

function db(): PDO {
  ensure_dirs();
  $dbPath = __DIR__ . '/../db/app.sqlite';
  $pdo = new PDO('sqlite:' . $dbPath, null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
  ]);
  return $pdo;
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

function rate_limit(string $key, int $maxRequests, int $windowSeconds): void {
  ensure_dirs();
  $ip = client_ip();
  $bucket = hash('sha256', $key . '|' . $ip);
  $file = __DIR__ . '/../storage/rl_' . $bucket . '.json';

  $now = time();
  $data = ['reset' => $now + $windowSeconds, 'count' => 0];

  if (is_file($file)) {
    $raw = file_get_contents($file);
    $tmp = json_decode($raw ?: '', true);
    if (is_array($tmp) && isset($tmp['reset'], $tmp['count'])) {
      $data = $tmp;
      if ($now > (int)$data['reset']) {
        $data = ['reset' => $now + $windowSeconds, 'count' => 0];
      }
    }
  }

  $data['count'] = ((int)$data['count']) + 1;
  file_put_contents($file, json_encode($data), LOCK_EX);

  if ($data['count'] > $maxRequests) {
    http_response_code(429);
    exit('Too many requests. Please try again later.');
  }
}

function safe_fetch_json(string $url): array {
  $allow = getenv('API_ALLOWLIST') ?: '';
  $allowHosts = array_filter(array_map('trim', explode(',', $allow)));

  $parts = parse_url($url);
  $host = $parts['host'] ?? '';
  if (!$host || !in_array($host, $allowHosts, true)) {
    throw new RuntimeException('Blocked by API allowlist');
  }

  $ctx = stream_context_create([
    'http' => [
      'method' => 'GET',
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
  if ($raw === false) {
    throw new RuntimeException('API request failed');
  }

  $data = json_decode($raw, true);
  if (!is_array($data)) {
    throw new RuntimeException('Invalid JSON from API');
  }
  return $data;
}

function csv_safe_cell(string $value): string {
  $trim = ltrim($value);
  if ($trim !== '' && preg_match('/^[=\+\-@]/', $trim)) {
    return "'" . $value;
  }
  return $value;
}
