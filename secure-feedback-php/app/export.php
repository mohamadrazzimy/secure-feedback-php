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
fputcsv($out, ['id', 'created_at', 'name', 'comment']);

foreach ($rows as $r) {
  fputcsv($out, [
    (int)$r['id'],
    $r['created_at'],
    csv_safe_cell((string)$r['name']),
    csv_safe_cell((string)$r['comment']),
  ]);
}
fclose($out);
