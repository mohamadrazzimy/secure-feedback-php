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
