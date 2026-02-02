<?php
require_once __DIR__ . '/lib/security.php';

csrf_start();
rate_limit('comment_post', 30, 60);

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
$contextTags = [];

function load_context(): array {
  $tags = [];

  $jsonPath = __DIR__ . '/data/context.json';
  if (is_file($jsonPath)) {
    $raw = file_get_contents($jsonPath);
    $data = json_decode($raw ?: '', true);
    if (is_array($data) && isset($data['tags']) && is_array($data['tags'])) {
      foreach ($data['tags'] as $t) {
        if (is_string($t) && strlen($t) <= 30) $tags[] = $t;
      }
    }
  }

  $csvPath = __DIR__ . '/data/context.csv';
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

$contextTags = load_context();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_verify();

  $name = trim((string)($_POST['name'] ?? ''));
  $comment = trim((string)($_POST['comment'] ?? ''));

  if ($name === '' || strlen($name) > 50) $errors[] = 'Name is required (max 50 chars).';
  if ($comment === '' || strlen($comment) > 800) $errors[] = 'Comment is required (max 800 chars).';

  if (!$errors) {
    $stmt = $pdo->prepare("INSERT INTO comments (created_at, name, comment) VALUES (:t, :n, :c)");
    $stmt->execute([
      ':t' => gmdate('c'),
      ':n' => $name,
      ':c' => $comment
    ]);
    header('Location: /');
    exit;
  }
}

$apiInfo = null;
try {
  $apiInfo = safe_fetch_json('https://api.github.com/');
} catch (Throwable $e) {
  $apiInfo = ['note' => 'API call blocked/failed: ' . $e->getMessage()];
}

$comments = $pdo->query("SELECT id, created_at, name, comment FROM comments ORDER BY id DESC LIMIT 50")->fetchAll();

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
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Secure Feedback Demo (PHP + SQLite)</title>
</head>
<body>
<h1>Secure Feedback Demo</h1>
<p>Go to <a href="/export.php">/export.php</a> for CSV export.</p>
</body>
</html>
