<?php
/**
 * common.php — shared logic for the Cudy SSH Enabler.
 *
 * Holds everything both front-ends use: the .env / models.txt loaders,
 * the AES crypto (BackupCrypt), the pure-PHP tar reader/writer, the
 * embedded etc/ + overlay/ tree, and the detect/patch helpers.
 *
 * KEY_BASE and MODELS are read from `.env` and `models.txt` sitting next to
 * this file. Entry points (cli.php, index.php) just `require` this file.
 */

error_reporting(E_ALL);

/**
 * Read KEY_BASE from a `.env` file next to this script.
 *
 * Expected line (quotes optional):   KEY_BASE=the-real-firmware-secret
 * Falls back to the placeholder "xxx" when the file or key is missing.
 */
function load_key_base(string $dir): string
{
	$fallback = 'xxx';
	$file     = $dir . '/.env';

	if (!is_file($file))
	{
		return $fallback;
	}

	foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line)
	{
		$line = trim($line);

		if ($line === '' || $line[0] === '#' || strpos($line, '=') === false)
		{
			continue;
		}

		[$name, $value] = explode('=', $line, 2);

		if (trim($name) !== 'KEY_BASE')
		{
			continue;
		}

		$value = trim($value);

		// Strip a single pair of surrounding quotes, if present.
		if (strlen($value) >= 2 && ($value[0] === '"' || $value[0] === "'") && $value[-1] === $value[0])
		{
			$value = substr($value, 1, -1);
		}

		return $value !== '' ? $value : $fallback;
	}

	return $fallback;
}

// The firmware's shared secret. Set it in a `.env` file next to this script:
//   KEY_BASE=the-real-firmware-secret
// The AES key is MD5("<MODEL>@" . KEY_BASE).
define('KEY_BASE', load_key_base(__DIR__));

/**
 * Read the list of router models from a `models.txt` file next to this script.
 *
 * One model per line, in the order they should be tried. Blank lines and lines
 * starting with `#` are ignored.
 */
function load_models(string $dir): array
{
	$file   = $dir . '/models.txt';
	$models = [];

	if (is_file($file))
	{
		foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line)
		{
			$line = trim($line);

			if ($line === '' || $line[0] === '#')
			{
				continue;
			}

			$models[] = $line;
		}
	}

	return $models;
}

// Models to try, in order — loaded from models.txt next to this script.
define('MODELS', load_models(__DIR__));

/* ------------------------------------------------------------------ */
/* Crypto (ported verbatim from decrypt.php / encrypt.php)             */
/* ------------------------------------------------------------------ */

class BackupCrypt
{
	const MAGIC       = 0xA1ECD5BD;
	const HEADER_SIZE = 0x30; // 48
	const CHUNK_SIZE  = 1024;

	private string $key;
	private string $iv;

	public function __construct(string $keySource)
	{
		$this->key = md5($keySource, true);
		$this->iv  = str_repeat("\x00", 16);
	}

	public function decrypt(string $data): array
	{
		if (strlen($data) < self::HEADER_SIZE)
		{
			throw new RuntimeException('File too small');
		}

		$header = $this->aesDecryptChunk(substr($data, 0, self::HEADER_SIZE));
		$magic  = unpack('V', substr($header, 0, 4))[1];

		if ($magic !== self::MAGIC)
		{
			throw new RuntimeException(sprintf('Magic mismatch (0x%08X)', $magic));
		}

		$timestamp = unpack('V', substr($header, 4, 4))[1];
		$random    = unpack('V', substr($header, 8, 4))[1];
		$build     = rtrim(substr($header, 16, 32), "\0\r\n\t ");

		$body      = substr($data, self::HEADER_SIZE);
		$bodyLen   = strlen($body);
		$pos       = 0;
		$plaintext = '';

		while ($pos < $bodyLen)
		{
			$chunk = substr($body, $pos, self::CHUNK_SIZE);
			$pos  += strlen($chunk);

			$plain = $this->aesDecryptChunk($chunk);

			if (strlen($chunk) < self::CHUNK_SIZE)
			{
				if ('' === trim(substr($plain, -16), "\x00"))
				{
					$plain = substr($plain, 0, -16);
				}
				else
				{
					$plainSize = strlen($plain);
					$removePos = 0;

					for ($i = $plainSize - 1; $i >= 0; $i--)
					{
						$removePos++;

						if (0 !== ord($plain[$i]))
						{
							$marker = ord($plain[$i]);
							$plain  = substr($plain, 0, -($removePos + $marker));
							break;
						}
					}
				}
			}

			$plaintext .= $plain;
		}

		return [
			'info' => [
				'magic'     => sprintf('0x%08X', $magic),
				'timestamp' => $timestamp,
				'datetime'  => date('Y-m-d H:i:s', $timestamp),
				'random'    => $random,
				'build'     => $build,
				'size'      => strlen($plaintext),
			],
			'payload' => $plaintext,
		];
	}

	public function encrypt(string $payload, string $buildString): string
	{
		$header =
			pack('V', self::MAGIC) .
			pack('V', time()) .
			pack('V', random_int(0, 0xffffffff)) .
			pack('V', 0) .
			str_pad(substr($buildString, 0, 32), 32, "\0");

		if (strlen($header) !== self::HEADER_SIZE)
		{
			throw new RuntimeException('Header size mismatch');
		}

		$out = $this->encryptChunk($header);
		$len = strlen($payload);
		$pos = 0;

		while ($pos < $len)
		{
			$chunk = substr($payload, $pos, self::CHUNK_SIZE);
			$pos  += strlen($chunk);

			if (strlen($chunk) < self::CHUNK_SIZE)
			{
				$chunkLength     = strlen($chunk);
				$marker          = $chunkLength % 16;
				$markerPadLength = ($chunkLength & 0xF) + $chunkLength + 16;

				$markerPad          = str_repeat("\x00", $markerPadLength);
				$markerPad[$marker] = chr($marker);

				$chunk .= $markerPad;
				$chunk  = $this->zeroPad($chunk, 16);

				$out .= substr($this->encryptChunk($chunk), 0, $markerPadLength);
			}
			else
			{
				$out .= $this->encryptChunk($chunk);
			}
		}

		return $out;
	}

	private function aesDecryptChunk(string $ciphertext): string
	{
		if ((strlen($ciphertext) % 16) !== 0)
		{
			$ciphertext = substr($ciphertext, 0, (int) (floor(strlen($ciphertext) / 16) * 16));
		}

		$plain = openssl_decrypt($ciphertext, 'AES-128-CBC', $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);

		if ($plain === false)
		{
			throw new RuntimeException('AES decrypt failed');
		}

		return $plain;
	}

	private function encryptChunk(string $plaintext): string
	{
		if ((strlen($plaintext) % 16) !== 0)
		{
			throw new RuntimeException('Plaintext length must be multiple of 16');
		}

		$encrypted = openssl_encrypt($plaintext, 'AES-128-CBC', $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);

		if ($encrypted === false)
		{
			throw new RuntimeException('AES encryption failed');
		}

		return $encrypted;
	}

	private function zeroPad(string $data, int $blockSize): string
	{
		$pad = $blockSize - (strlen($data) % $blockSize);

		if ($pad === 0)
		{
			$pad = $blockSize;
		}

		return $data . str_repeat("\x00", $pad);
	}
}

/* ------------------------------------------------------------------ */
/* Pure-PHP tar (USTAR) reader / writer                               */
/* ------------------------------------------------------------------ */

function tar_parse(string $data): array
{
	$entries  = [];
	$len      = strlen($data);
	$off      = 0;
	$longName = null;

	while ($off + 512 <= $len)
	{
		$hdr  = substr($data, $off, 512);
		$off += 512;

		if (trim($hdr, "\0") === '')
		{
			break;
		}

		$name   = rtrim(substr($hdr, 0, 100), "\0");
		$mode   = (int) octdec(trim(substr($hdr, 100, 8)) ?: '0');
		$uid    = (int) octdec(trim(substr($hdr, 108, 8)) ?: '0');
		$gid    = (int) octdec(trim(substr($hdr, 116, 8)) ?: '0');
		$size   = (int) octdec(trim(substr($hdr, 124, 12)) ?: '0');
		$mtime  = (int) octdec(trim(substr($hdr, 136, 12)) ?: '0');
		$type   = substr($hdr, 156, 1);
		$uname  = rtrim(substr($hdr, 265, 32), "\0");
		$gname  = rtrim(substr($hdr, 297, 32), "\0");
		$prefix = rtrim(substr($hdr, 345, 155), "\0");

		$content = substr($data, $off, $size);
		$off    += (int) (ceil($size / 512) * 512);

		if ($type === 'L')
		{
			$longName = rtrim($content, "\0");
			continue;
		}

		if ($prefix !== '')
		{
			$name = $prefix . '/' . $name;
		}

		if ($longName !== null)
		{
			$name     = $longName;
			$longName = null;
		}

		$entries[] = compact('name', 'mode', 'uid', 'gid', 'size', 'mtime', 'type', 'content', 'uname', 'gname');
	}

	return $entries;
}

function tar_header(string $name, int $mode, int $uid, int $gid, int $size, int $mtime, string $type, string $uname, string $gname, string $prefix): string
{
	$h  = str_pad(substr($name, 0, 100), 100, "\0");
	$h .= sprintf("%07o\0", $mode & 0777);
	$h .= sprintf("%07o\0", $uid);
	$h .= sprintf("%07o\0", $gid);
	$h .= sprintf("%011o\0", $size);
	$h .= sprintf("%011o\0", $mtime);
	$h .= str_repeat(' ', 8);
	$h .= $type;
	$h .= str_repeat("\0", 100);
	$h .= "ustar\x0000";
	$h .= str_pad(substr($uname ?: 'root', 0, 32), 32, "\0");
	$h .= str_pad(substr($gname ?: 'root', 0, 32), 32, "\0");
	$h .= str_repeat("\0", 16);
	$h .= str_pad(substr($prefix, 0, 155), 155, "\0");
	$h  = str_pad($h, 512, "\0");

	$sum = 0;
	for ($i = 0; $i < 512; $i++)
	{
		$sum += ord($h[$i]);
	}

	$chk = sprintf("%06o\0 ", $sum);

	return substr($h, 0, 148) . $chk . substr($h, 156);
}

function tar_build(array $entries): string
{
	$out = '';

	foreach ($entries as $e)
	{
		$name = $e['name'];
		$type = $e['type'];
		$size = ($type === '5') ? 0 : strlen($e['content']);

		$prefix = '';

		if (strlen($name) > 100)
		{
			$split = strrpos(substr($name, 0, 155), '/');

			if ($split !== false && (strlen($name) - $split - 1) <= 100)
			{
				$prefix = substr($name, 0, $split);
				$short  = substr($name, $split + 1);
			}
			else
			{
				$out  .= tar_header('././@LongLink', 0, 0, 0, strlen($name) + 1, 0, 'L', 'root', 'root', '');
				$out  .= str_pad($name . "\0", (int) (ceil((strlen($name) + 1) / 512) * 512), "\0");
				$short = substr($name, 0, 100);
			}
		}
		else
		{
			$short = $name;
		}

		$out .= tar_header($short, $e['mode'], $e['uid'] ?? 0, $e['gid'] ?? 0, $size, $e['mtime'] ?? time(), $type, $e['uname'] ?? 'root', $e['gname'] ?? 'root', $prefix);

		if ($size > 0)
		{
			$out .= $e['content'];
			$pad  = (512 - ($size % 512)) % 512;
			$out .= str_repeat("\0", $pad);
		}
	}

	$out .= str_repeat("\0", 1024);

	return $out;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

function tar_upsert(array &$entries, array &$index, array $entry): void
{
	$key = rtrim($entry['name'], '/');

	if (isset($index[$key]))
	{
		$entries[$index[$key]] = $entry;
	}
	else
	{
		$entries[]   = $entry;
		$index[$key] = count($entries) - 1;
	}
}

/**
 * The etc/ and overlay/ tree, embedded directly in this script so no
 * external folders are needed next to index.php.
 *
 * Each entry: ['name' => tar path, 'dir' => bool, 'content' => string, 'mode' => int]
 * Directories come before the files they contain.
 */
function embedded_entries(): array
{
	// etc/rc.local — the debug/SSH payload. Nowdoc keeps it byte-for-byte
	// ($NEWPASS etc. are NOT interpolated). The password is injected later.
	$rcLocal = <<<'RCLOCAL'
# Put your custom commands here that should be executed once
# the system init finished. By default this file does nothing.

echo 3 > /proc/sys/vm/drop_caches
# --- cudy-debug-backup BEGIN ---

# Delete 11_fix_passwd to prevent it from overwriting root password
rm -f /etc/uci-defaults/11_fix_passwd 2>/dev/null || true

# Patch init.d scripts to bypass bdinfo dbg check for SSH/telnet
sed -i 's/\[ "$(bdinfo dbg)" == OK \]/#[ "$(bdinfo dbg)" == OK ]/g' /etc/init.d/dropbear 2>/dev/null || true
sed -i 's/\[ "$(bdinfo dbg)" == OK \]/#[ "$(bdinfo dbg)" == OK ]/g' /etc/init.d/telnet 2>/dev/null || true

# Create debug flag
touch /etc/rom_dbg 2>/dev/null || true
mkdir -p /overlay/upper/etc 2>/dev/null || true
: > /overlay/upper/etc/rom_dbg 2>/dev/null || true

# Enable ttylogin
uci -q set system.@system[0].ttylogin='1' 2>/dev/null || true
uci -q commit system 2>/dev/null || true

# Set root password
NEWPASS='12345678'
(echo "$NEWPASS"; sleep 1; echo "$NEWPASS") | passwd root 2>/dev/null || true

# SSH (dropbear)
/etc/init.d/dropbear enable 2>/dev/null || true
/etc/init.d/dropbear restart 2>/dev/null || /etc/init.d/dropbear start 2>/dev/null || true

# Telnet (если есть init.d/telnet), иначе пробуем telnetd напрямую
/etc/init.d/telnet enable 2>/dev/null || true
/etc/init.d/telnet restart 2>/dev/null || /etc/init.d/telnet start 2>/dev/null || true
if ! ps | grep -q '[t]elnetd'; then
  (telnetd -l /bin/login -p 23 2>/dev/null || /usr/sbin/telnetd -l /bin/login -p 23 2>/dev/null || true) &
fi

# --- cudy-debug-backup END ---
exit 0

RCLOCAL;

	return [
		['name' => 'etc/',                 'dir' => true,  'content' => '',       'mode' => 0755],
		['name' => 'etc/rc.local',         'dir' => false, 'content' => $rcLocal, 'mode' => 0755],
		['name' => 'etc/rom_dbg',          'dir' => false, 'content' => '',       'mode' => 0644],
		['name' => 'overlay/',             'dir' => true,  'content' => '',       'mode' => 0755],
		['name' => 'overlay/etc/',         'dir' => true,  'content' => '',       'mode' => 0755],
		['name' => 'overlay/etc/rom_dbg',  'dir' => false, 'content' => '',       'mode' => 0644],
	];
}

function inject_password(string $content, string $pass): string
{
	$escaped = str_replace("'", "'\\''", $pass);

	$new = preg_replace('/^(\s*NEWPASS=).*$/m', "\${1}'" . $escaped . "'", $content, 1, $count);

	return $count === 0 ? $content : $new;
}

/* ------------------------------------------------------------------ */
/* Core processing — collects a log, returns the patched bytes        */
/* ------------------------------------------------------------------ */

/**
 * @return array{ok:bool, log:array<int,array{t:string,m:string}>, bin:?string, name:?string}
 */
function process_backup(string $raw, string $pass, string $baseName, bool $quiet = false): array
{
	$log = [];
	$add = function (string $t, string $m) use (&$log) { $log[] = ['t' => $t, 'm' => $m]; };

	/* 1. Auto-detect model */
	$crypt = $model = $decrypted = null;

	foreach (MODELS as $m)
	{
		$try = new BackupCrypt($m . '@' . KEY_BASE);

		try
		{
			$decrypted = $try->decrypt($raw);
			$crypt     = $try;
			$model     = $m;
			if (!$quiet) { $add('+', 'Model detected: <b>' . htmlspecialchars($m) . '</b>'); }
			break;
		}
		catch (Throwable $e)
		{
			// Silently try the next model.
		}
	}

	if ($crypt === null)
	{
		$add('!', 'Could not decrypt with any known model key.');
		return ['ok' => false, 'log' => $log, 'bin' => null, 'name' => null];
	}

	$info    = $decrypted['info'];
	$payload = $decrypted['payload'];

	if (!$quiet)
	{
		$add(' ', sprintf('build=%s · date=%s · payload=%d bytes',
			$info['build'] !== '' ? htmlspecialchars($info['build']) : '(none)', $info['datetime'], $info['size']));
	}

	/* 2. gunzip + untar */
	$tar = @gzdecode($payload);

	if ($tar === false)
	{
		$add('!', 'Payload is not a valid gzip archive.');
		return ['ok' => false, 'log' => $log, 'bin' => null, 'name' => null];
	}

	$entries = tar_parse($tar);
	$index   = [];
	foreach ($entries as $i => $e)
	{
		$index[rtrim($e['name'], '/')] = $i;
	}

	/* 3. Merge the embedded etc/ and overlay/ tree */
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

	$add('+', 'SSH enabled');

	/* 4. Apply the SSH password to the archive's etc/rc.local */
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
			$add('+', 'Set NEWPASS in etc/rc.local');
		}
		else
		{
			$add('!', 'etc/rc.local has no NEWPASS= line; left unchanged.');
		}
	}
	else
	{
		$add('!', 'No etc/rc.local in archive; SSH password not applied.');
	}

	/* 5. Re-tar, gzip, re-encrypt */
	$newTar = tar_build($entries);
	$newGz  = gzencode($newTar, 9);
	$build  = $info['build'] !== '' ? $info['build'] : 'for.4pda.users';
	$binOut = $crypt->encrypt($newGz, $build);

	$outName = preg_replace('/(\.bin)?$/i', '-patched.bin', $baseName, 1);

	$add('v', sprintf('Done. %s (%d bytes), model=%s', htmlspecialchars($outName), strlen($binOut), htmlspecialchars($model)));

	return ['ok' => true, 'log' => $log, 'bin' => $binOut, 'name' => $outName];
}

/* ------------------------------------------------------------------ */
/* Request handling                                                   */
/* ------------------------------------------------------------------ */

/** Detect the model from an uploaded blob (no patching). */
function api_detect(string $raw): array
{
	foreach (MODELS as $m)
	{
		$try = new BackupCrypt($m . '@' . KEY_BASE);

		try
		{
			$d = $try->decrypt($raw);
		}
		catch (Throwable $e)
		{
			continue; // try next model
		}

		$tar = @gzdecode($d['payload']);

		if ($tar === false)
		{
			return ['ok' => false, 'log' => [['t' => 'x', 'm' => 'Decrypted, but the payload is not a valid gzip archive.']]];
		}

		$info  = $d['info'];
		$build = $info['build'] !== '' ? htmlspecialchars($info['build']) : '(none)';

		return [
			'ok'    => true,
			'model' => $m,
			'log'   => [
				['t' => '+', 'm' => 'Model detected: <b>' . htmlspecialchars($m) . '</b>'],
				['t' => ' ', 'm' => sprintf('build=%s · date=%s · payload=%d bytes', $build, $info['datetime'], $info['size'])],
				['t' => ' ', 'm' => 'ready — enter the ssh password, then run.'],
			],
		];
	}

	return ['ok' => false, 'log' => [['t' => 'x', 'm' => 'Could not decrypt with any known model key. Is this a Cudy backup?']]];
}
