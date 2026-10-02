<?php
/**
 * cli.php — Cudy SSH Enabler (command-line edition).
 *
 * Thin front-end: argument parsing and interactive flow. All crypto/tar/overlay
 * logic lives in common.php.
 *
 * Usage:
 *   php cli.php <input.bin> [output.bin] [--pass=<sshpass>] [--model=<model>]
 */

require __DIR__ . '/common.php';

function prompt_line(string $question): string
{
	fwrite(STDERR, $question);
	$line = fgets(STDIN);

	return $line === false ? '' : rtrim($line, "\r\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

function main(array $argv): int
{
	$args     = array_slice($argv, 1);
	$positional = [];
	$optPass  = null;
	$optModel = null;

	foreach ($args as $a)
	{
		if (strncmp($a, '--pass=', 7) === 0)
		{
			$optPass = substr($a, 7);
		}
		elseif (strncmp($a, '--model=', 8) === 0)
		{
			$optModel = substr($a, 8);
		}
		elseif ($a === '-h' || $a === '--help')
		{
			fwrite(STDERR, "Usage: php cli.php <input.bin> [output.bin] [--pass=<sshpass>] [--model=<model>]\n");
			fwrite(STDERR, 'Supported models: ' . implode(', ', MODELS) . "\n");
			return 0;
		}
		else
		{
			$positional[] = $a;
		}
	}

	if (count($positional) < 1)
	{
		fwrite(STDERR, "Usage: php cli.php <input.bin> [output.bin] [--pass=<sshpass>] [--model=<model>]\n");
		fwrite(STDERR, 'Supported models: ' . implode(', ', MODELS) . "\n");
		return 1;
	}

	$inputFile  = $positional[0];
	$outputFile = $positional[1] ?? preg_replace('/(\.bin)?$/i', '-patched.bin', $inputFile, 1);

	if (!is_file($inputFile))
	{
		fwrite(STDERR, "Input file not found: $inputFile\n");
		return 1;
	}

	$raw = file_get_contents($inputFile);

	/* --- 1. Auto-detect model by trying keys until magic matches --- */

	$candidates = $optModel ? [$optModel] : MODELS;
	$crypt      = null;
	$model      = null;
	$decrypted  = null;

	foreach ($candidates as $m)
	{
		$try = new BackupCrypt($m . '@' . KEY_BASE);

		try
		{
			$decrypted = $try->decrypt($raw);
			$crypt     = $try;
			$model     = $m;
			fwrite(STDERR, "[+] Model detected: $m\n");
			break;
		}
		catch (Throwable $e)
		{
			// Silently try the next model.
		}
	}

	if ($crypt === null)
	{
		fwrite(STDERR, "\n[!] Could not decrypt with any known model key.\n");
		fwrite(STDERR, 'Supported models: ' . implode(', ', MODELS) . "\n");
		return 2;
	}

	$info    = $decrypted['info'];
	$payload = $decrypted['payload'];

	fwrite(STDERR, sprintf(
		"    build=%s  date=%s  payload=%d bytes\n",
		$info['build'] !== '' ? $info['build'] : '(none)',
		$info['datetime'],
		$info['size']
	));

	/* --- 2. gunzip + untar --- */

	$tar = @gzdecode($payload);

	if ($tar === false)
	{
		fwrite(STDERR, "[!] Payload is not a valid gzip archive.\n");
		return 3;
	}

	$entries = tar_parse($tar);
	$index   = [];
	foreach ($entries as $i => $e)
	{
		$index[rtrim($e['name'], '/')] = $i;
	}

	/* --- 3. Ask for SSH password --- */

	$pass = $optPass;

	while ($pass === null || $pass === '')
	{
		$pass = prompt_line('Enter the SSH (root) password to set [NEWPASS]: ');

		if ($pass === '')
		{
			fwrite(STDERR, "    Password cannot be empty.\n");
		}
	}

	/* --- 4. Merge the embedded etc/ and overlay/ tree --- */

	$added = 0;

	foreach (embedded_entries() as $f)
	{
		$entry = [
			'name'    => $f['name'],
			'mode'    => $f['mode'],
			'uid'     => 0,
			'gid'     => 0,
			'size'    => $f['dir'] ? 0 : strlen($f['content']),
			'mtime'   => time(),
			'type'    => $f['dir'] ? '5' : '0',
			'content' => $f['content'],
			'uname'   => 'root',
			'gname'   => 'root',
		];

		tar_upsert($entries, $index, $entry);
		$added++;
	}

	fwrite(STDERR, "[+] SSH enabled\n");

	/* --- 4b. Apply the SSH password to the archive's etc/rc.local, no
	   matter whether it came from the local folder or was already injected
	   into this backup. This guarantees the user is always asked and the
	   password is always (re)set. --- */

	$rcKey = 'etc/rc.local';

	if (isset($index[$rcKey]))
	{
		$i      = $index[$rcKey];
		$before = $entries[$i]['content'];
		$after  = inject_password($before, $pass);

		$entries[$i]['content'] = $after;
		$entries[$i]['size']    = strlen($after);

		if ($after !== $before)
		{
			fwrite(STDERR, "[+] Set NEWPASS in etc/rc.local\n");
		}
		else
		{
			fwrite(STDERR, "[!] etc/rc.local has no NEWPASS= line; left unchanged.\n");
		}
	}
	else
	{
		fwrite(STDERR, "[!] No etc/rc.local found in archive; SSH password not applied.\n");
	}

	/* --- 5. Re-tar, gzip, re-encrypt --- */

	$newTar = tar_build($entries);
	$newGz  = gzencode($newTar, 9);

	$build  = $info['build'] !== '' ? $info['build'] : 'for.4pda.users';
	$binOut = $crypt->encrypt($newGz, $build);

	if (file_put_contents($outputFile, $binOut) === false)
	{
		fwrite(STDERR, "[!] Failed to write output: $outputFile\n");
		return 4;
	}

	fwrite(STDERR, sprintf("\n[✓] Done. Wrote %s (%d bytes), model=%s\n", $outputFile, strlen($binOut), $model));

	return 0;
}

exit(main($argv));
