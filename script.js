'use strict';

(function () {
	var drop   = document.getElementById('drop');
	var input  = document.getElementById('binfile');
	var fname  = document.getElementById('fname');
	var pwstep = document.getElementById('pwstep');
	var pass   = document.getElementById('pass');
	var eye    = document.getElementById('eye');
	var go     = document.getElementById('go');
	var form   = document.getElementById('form');
	var outcard = document.getElementById('outcard');
	var tbody  = document.getElementById('tbody');
	var dlrow  = document.getElementById('dlrow');
	var prompt = document.getElementById('prompt');

	var GLYPH = { '+':'   ', '-':'   ', '!':'[!]', 'v':'[✓]', 'x':'[x]', ' ':'   ' };
	var CLASS = { '+':'ok', '-':'dim', '!':'warn', 'v':'done', 'x':'err', ' ':'info' };

	var cursorEl = null;
	var delay = 0;
	var detected = false;

	function human(b) {
		if (b < 1024) return b + ' B';
		if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
		return (b / 1048576).toFixed(2) + ' MB';
	}

	// touch devices: the on-screen keyboard covers the log, so scroll it into view instead of focusing
	var touch = window.matchMedia && window.matchMedia('(pointer: coarse)').matches;

	function showOut() {
		if (outcard.style.display === 'none') { outcard.style.display = ''; }
	}

	function revealOut() {
		if (touch && outcard.scrollIntoView) { outcard.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
	}

	function clearLog() {
		tbody.innerHTML = '';
		dlrow.style.display = 'none';
		dlrow.innerHTML = '';
		delay = 0;
		cursorEl = null;
	}

	function removeCursor() {
		if (cursorEl && cursorEl.parentNode) { cursorEl.parentNode.removeChild(cursorEl); }
		cursorEl = null;
	}

	function addLine(type, html) {
		removeCursor();
		var ln = document.createElement('div');
		ln.className = 'ln ' + (CLASS[type] || 'info');
		ln.style.animationDelay = delay.toFixed(2) + 's';
		delay += 0.06;
		var g = document.createElement('span');
		g.className = 'g';
		g.textContent = GLYPH[type] || '   ';
		var s = document.createElement('span');
		s.innerHTML = html; // messages are built & escaped server-side
		ln.appendChild(g);
		ln.appendChild(s);
		tbody.appendChild(ln);
	}

	function addCursor() {
		removeCursor();
		var ln = document.createElement('div');
		ln.className = 'ln';
		ln.style.animationDelay = delay.toFixed(2) + 's';
		var g = document.createElement('span');
		g.className = 'g';
		g.textContent = '>';
		var c = document.createElement('span');
		c.className = 'cursor';
		ln.appendChild(g);
		ln.appendChild(c);
		tbody.appendChild(ln);
		cursorEl = ln;
	}

	function renderLog(log) {
		if (!log) return;
		for (var i = 0; i < log.length; i++) { addLine(log[i].t, log[i].m); }
	}

	function setPrompt(fileName, status) {
		var span = status === 'ok' ? '<span class="st-ok">[ok]</span>'
			: status === 'err' ? '<span class="st-err">[failed]</span>' : '';
		prompt.innerHTML = '<span class="p">root@cudy</span>:~# ./enable-ssh &lt;' + escapeHtml(fileName) + '&gt; ' + span;
	}

	function escapeHtml(s) {
		return String(s).replace(/[&<>"']/g, function (c) {
			return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
		});
	}

	// ---- step 1: detect on file select ----
	function onFile() {
		if (!input.files || !input.files.length) return;
		var f = input.files[0];
		fname.textContent = '» ' + f.name + '  (' + human(f.size) + ')';
		drop.classList.add('has');

		detected = false;
		pwstep.classList.add('step-hidden');
		showOut();
		clearLog();
		setPrompt(f.name, '');
		addLine(' ', 'detecting model…');
		addCursor();
		drop.classList.add('busy');
		revealOut();

		var fd = new FormData();
		fd.append('action', 'detect');
		fd.append('binfile', f);

		fetch('index.php', { method: 'POST', body: fd })
			.then(function (r) { return r.json(); })
			.then(function (res) {
				drop.classList.remove('busy');
				clearLog();
				setPrompt(f.name, res.ok ? 'ok' : 'err');
				renderLog(res.log);
				if (res.ok) {
					detected = true;
					pwstep.classList.remove('step-hidden');
					if (touch) { revealOut(); } else { pass.focus(); }
				} else {
					detected = false;
					addCursor();
					revealOut();
				}
			})
			.catch(function () {
				drop.classList.remove('busy');
				clearLog();
				setPrompt(f.name, 'err');
				addLine('x', 'Network error while detecting the model.');
				addCursor();
				revealOut();
			});
	}

	// ---- step 2: patch on run ----
	function onRun() {
		if (!detected || !input.files || !input.files.length) return;
		var f = input.files[0];
		if (!pass.value) { pass.focus(); return; }

		go.classList.add('loading');
		go.querySelector('.lbl').textContent = 'working…';
		addLine(' ', 'patching…');
		addCursor();

		var fd = new FormData();
		fd.append('action', 'patch');
		fd.append('binfile', f);
		fd.append('pass', pass.value);

		fetch('index.php', { method: 'POST', body: fd })
			.then(function (r) { return r.json(); })
			.then(function (res) {
				go.classList.remove('loading');
				go.querySelector('.lbl').textContent = '▶ run';
				removeCursor();
				renderLog(res.log);
				setPrompt(f.name, res.ok ? 'ok' : 'err');
				if (touch) { pass.blur(); revealOut(); }
				if (res.ok && res.data) {
					var href = 'data:application/octet-stream;base64,' + res.data;
					var a = document.createElement('a');
					a.className = 'dl';
					a.id = 'dl';
					a.href = href;
					a.setAttribute('download', res.name);
					a.textContent = '⬇ download ' + res.name;
					var note = document.createElement('span');
					note.className = 'dlnote';
					note.textContent = '# download starts automatically — otherwise click above.';
					dlrow.appendChild(a);
					dlrow.appendChild(note);
					dlrow.style.display = '';
					a.click();
				} else {
					addCursor();
				}
			})
			.catch(function () {
				go.classList.remove('loading');
				go.querySelector('.lbl').textContent = '▶ run';
				removeCursor();
				addLine('x', 'Network error while patching.');
				addCursor();
			});
	}

	// ---- wiring ----
	input.addEventListener('change', onFile);
	['dragenter', 'dragover'].forEach(function (e) {
		drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.add('drag'); });
	});
	['dragleave', 'drop'].forEach(function (e) {
		drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.remove('drag'); });
	});
	drop.addEventListener('drop', function (ev) {
		if (ev.dataTransfer.files.length) { input.files = ev.dataTransfer.files; onFile(); }
	});

	eye.addEventListener('click', function () {
		var p = pass.type === 'password';
		pass.type = p ? 'text' : 'password';
		eye.classList.toggle('on', p);
		pass.focus();
	});

	go.addEventListener('click', onRun);
	pass.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); onRun(); } });
	form.addEventListener('submit', function (ev) { ev.preventDefault(); onRun(); });
})();
