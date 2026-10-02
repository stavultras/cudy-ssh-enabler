<?php
/**
 * index.php — Cudy SSH Enabler (web edition).
 *
 * Thin front-end: a JSON API (detect / patch) plus serving the HTML page.
 * All crypto/tar/overlay logic lives in common.php.
 */

require __DIR__ . '/common.php';

/* ------------------------------------------------------------------ */
/* Router: JSON API for detect/patch, otherwise serve the HTML page.  */
/* ------------------------------------------------------------------ */

$action = $_POST['action'] ?? '';

if ($action === 'detect' || $action === 'patch')
{
	header('Content-Type: application/json');

	if (!isset($_FILES['binfile']) || $_FILES['binfile']['error'] !== UPLOAD_ERR_OK)
	{
		echo json_encode(['ok' => false, 'log' => [['t' => 'x', 'm' => 'No file uploaded, or the upload failed (check upload_max_filesize).']]]);
		exit;
	}

	$raw  = file_get_contents($_FILES['binfile']['tmp_name']);
	$name = basename($_FILES['binfile']['name']);

	if ($action === 'detect')
	{
		echo json_encode(api_detect($raw));
		exit;
	}

	// action === 'patch'
	$pass = $_POST['pass'] ?? '';

	if ($pass === '')
	{
		echo json_encode(['ok' => false, 'log' => [['t' => 'x', 'm' => 'The SSH password cannot be empty.']]]);
		exit;
	}

	try
	{
		$r = process_backup($raw, $pass, $name, true);
	}
	catch (Throwable $e)
	{
		echo json_encode(['ok' => false, 'log' => [['t' => 'x', 'm' => 'Unexpected error: ' . htmlspecialchars($e->getMessage())]]]);
		exit;
	}

	if (!$r['ok'])
	{
		echo json_encode(['ok' => false, 'log' => $r['log']]);
		exit;
	}

	echo json_encode([
		'ok'   => true,
		'log'  => $r['log'],
		'name' => $r['name'],
		'data' => base64_encode($r['bin']),
	]);
	exit;
}

/* Normal request → serve the HTML view, injecting the supported model list. */
header('Content-Type: text/html; charset=utf-8');
$page = file_get_contents(__DIR__ . '/page.html');
echo str_replace('{{MODELS}}', htmlspecialchars(implode(', ', MODELS)), $page);
exit;

