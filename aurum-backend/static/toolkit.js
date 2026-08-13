// this file just talks to the server and shows the result on the page.
// all the actual password checking (strength, hashes, breach check, generator)
// happens in Python, in app.py, under /api/password/...

var pwInput = document.getElementById('pwInput');
var toggleVis = document.getElementById('toggleVis');
var isVisible = false;
var nameInput = document.getElementById('patientName');
var emailInput = document.getElementById('patientEmail');


toggleVis.addEventListener('click', function () {
  isVisible = !isVisible;
  if (isVisible) {
    pwInput.type = 'text';
    toggleVis.textContent = 'Hide';
  } else {
    pwInput.type = 'password';
    toggleVis.textContent = 'Show';
  }
});

var meterFill = document.getElementById('meterFill');
var scoreWord = document.getElementById('scoreWord');
var scoreNum = document.getElementById('scoreNum');
var crackTime = document.getElementById('crackTime');
var explainBox = document.getElementById('explainBox');
var policyGrid = document.getElementById('policyGrid');
var hashBox = document.getElementById('hashBox');
var hibpResult = document.getElementById('hibpResult');
var submitBtn = document.getElementById('submitBtn');

var scoreColors = ['#e5544b', '#e5544b', '#e8b339', '#d4af37', '#8fd35c'];

var POLICY_LABELS = [
  ['len8', 'At least 8 characters'],
  ['len12', 'At least 12 characters (recommended)'],
  ['upper', 'At least one uppercase letter'],
  ['lower', 'At least one lowercase letter'],
  ['num', 'At least one number'],
  ['sym', 'At least one special symbol'],
  ['nospace', 'No spaces'],
  ['norepeat', 'No 3+ repeated characters in a row'],
];

var CRITICAL_IDS = ['len8', 'upper', 'lower', 'num'];

function renderPolicy(policy, hasPw) {
  var html = '';
  for (var i = 0; i < POLICY_LABELS.length; i++) {
    var id = POLICY_LABELS[i][0];
    var label = POLICY_LABELS[i][1];
    var ok = policy ? policy[id] : false;
    var dotClass = '';
    if (hasPw) {
      dotClass = ok ? 'pass' : 'fail';
    }
    html += '<div class="policy-item"><span class="dot ' + dotClass + '"></span>' + label + '</div>';
  }
  policyGrid.innerHTML = html;
}

function renderHashes(hashes) {
  if (!hashes || !hashes.sha256) {
    hashBox.innerHTML = '<p class="empty">The same password will be shown here using several hashing algorithms.</p>';
    return;
  }

  var rows = [
    ['MD5', hashes.md5, 'Very weak - mathematically broken and extremely fast to brute-force. Never used for real passwords.'],
    ['SHA-1', hashes.sha1, 'Better than MD5, but still very fast and not secure for storing passwords.'],
    ['SHA-256', hashes.sha256, 'A strong general-purpose hash, but still fast - not sufficient alone for storing passwords.'],
  ];

  var html = '';
  for (var i = 0; i < rows.length; i++) {
    var algo = rows[i][0];
    var val = rows[i][1];
    var note = rows[i][2];
    html += '<div class="hash-row"><div class="algo">' + algo + '</div>' +
      '<div><div class="val">' + val + '</div><div class="muted" style="margin-top:4px">' + note + '</div></div></div>';
  }

  html += '<div class="muted" style="margin-top:14px;padding-top:12px;border-top:1px solid var(--panel-line)">' +
    'Computed server-side in Python. What AURUM actually stores in the database is a salted ' +
    '<b style="color:var(--gold)">PBKDF2-SHA256</b> hash, not the raw digests shown above.</div>';

  hashBox.innerHTML = html;
}

function render(data) {
  var hasPw = data.score !== null && data.score !== undefined;

  if (!hasPw) {
    meterFill.style.width = '0%';
    scoreWord.textContent = '-';
    scoreNum.textContent = '0/4';
    crackTime.textContent = 'Estimated crack time: -';
    explainBox.innerHTML = '<p class="empty">Start typing a password above to see the analysis.</p>';
  } else {
    var pct = (data.score + 1) * 20;
    meterFill.style.width = pct + '%';
    meterFill.style.background = scoreColors[data.score];
    scoreWord.textContent = data.score_word;
    scoreWord.style.color = scoreColors[data.score];
    scoreNum.textContent = data.score + '/4';
    crackTime.textContent = 'Estimated crack time (offline attack): ' + data.crack_time;

    if (data.reasons.length === 0) {
      explainBox.innerHTML = '<p class="empty" style="color:var(--gold)">No obvious weaknesses - this password looks good.</p>';
    } else {
      var listHtml = '<ul class="explain-list">';
      for (var i = 0; i < data.reasons.length; i++) {
        listHtml += '<li>' + data.reasons[i] + '</li>';
      }
      listHtml += '</ul>';
      explainBox.innerHTML = listHtml;
    }
  }

  renderPolicy(data.policy, hasPw);
  renderHashes(data.hashes);

      // NEW: Button is only enabled if the zxcvbn score is 3 (Strong) or 4 (Very Strong)
  var isScoreStrongEnough = (data.score >= 3);
  submitBtn.disabled = !(hasPw && isScoreStrongEnough);


}

// wait a bit after the user stops typing before calling the server,
// so we don't send a request on every single keystroke
var debounceTimer = null;

function analyze(pw) {
  if (!pw) {
    render({ score: null, policy: {}, reasons: [], hashes: {} });
    return;
  }
  fetch('/api/password/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      password: pw,
      name: nameInput ? nameInput.value : "",
      email: emailInput ? emailInput.value : ""
    }),
  })

    .then(function (res) { return res.json(); })
    .then(function (data) { render(data); })
    .catch(function (err) {
      explainBox.innerHTML = '<p class="empty" style="color:var(--danger)">Could not reach the analysis server. Is app.py running?</p>';
    });
}

pwInput.addEventListener('input', function () {
  var pw = pwInput.value;
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(function () { analyze(pw); }, 220);

  hibpResult.className = 'hibp-result hibp-idle';
  hibpResult.textContent = 'Click the button to check whether this password has appeared in known breaches. Only the first 5 characters of its hash are sent (k-anonymity) - the check itself runs on the AURUM server, in Python.';
});

// ---------- breach check button ----------
document.getElementById('checkBreach').addEventListener('click', function () {
  var pw = pwInput.value;
  if (!pw) {
    hibpResult.className = 'hibp-result hibp-idle';
    hibpResult.textContent = 'Type a password first.';
    return;
  }

  hibpResult.className = 'hibp-result hibp-idle';
  hibpResult.textContent = 'Checking...';

  fetch('/api/password/breach', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: pw }),
  })
    .then(function (res) { return res.json(); })
    .then(function (data) {
      if (!data.ok) {
        hibpResult.className = 'hibp-result hibp-breached';
        hibpResult.textContent = data.error || 'Could not complete the breach check right now.';
        return;
      }
      if (data.breached) {
        hibpResult.className = 'hibp-result hibp-breached';
        hibpResult.textContent = 'This password has appeared in known breaches ' + data.count.toLocaleString('en') + ' times before. Please choose a different one.';
      } else {
        hibpResult.className = 'hibp-result hibp-safe';
        hibpResult.textContent = 'Not found in known breach databases.';
      }
    })
    .catch(function (err) {
      hibpResult.className = 'hibp-result hibp-breached';
      hibpResult.textContent = 'Could not reach the server right now. Please try again.';
    });
});

// ---------- generator ----------
var lenSlider = document.getElementById('lenSlider');
var lenVal = document.getElementById('lenVal');
lenSlider.addEventListener('input', function () {
  lenVal.textContent = lenSlider.value;
});

document.getElementById('genBtn').addEventListener('click', function () {
  var genText = document.getElementById('genText');
  var payload = {
    length: parseInt(lenSlider.value),
    upper: document.getElementById('optUpper').checked,
    lower: document.getElementById('optLower').checked,
    num: document.getElementById('optNum').checked,
    sym: document.getElementById('optSym').checked,
  };

  fetch('/api/password/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
    .then(function (res) { return res.json(); })
    .then(function (data) {
      if (!data.ok) {
        genText.textContent = data.error;
        return;
      }
      genText.textContent = data.password;
      genText.classList.remove('muted');
    })
    .catch(function (err) {
      genText.textContent = 'Could not reach the server.';
    });
});

document.getElementById('useGen').addEventListener('click', function () {
  var t = document.getElementById('genText').textContent;
  if (t && t.indexOf('Click') === -1 && t.indexOf('Select') === -1) {
    pwInput.value = t;
    pwInput.dispatchEvent(new Event('input'));
    isVisible = true;
    pwInput.type = 'text';
    toggleVis.textContent = 'Hide';
  }
});

document.getElementById('copyGen').addEventListener('click', function () {
  var t = document.getElementById('genText').textContent;
  if (t && t.indexOf('Click') === -1 && t.indexOf('Select') === -1) {
    navigator.clipboard.writeText(t);
    var btn = document.getElementById('copyGen');
    var oldText = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(function () { btn.textContent = oldText; }, 1200);
  }
});

// ---------- advanced section toggle ----------
var advToggle = document.getElementById('advToggle');
var advBody = document.getElementById('advBody');

function toggleAdv() {
  var open = advBody.classList.toggle('open');
  advToggle.setAttribute('aria-expanded', open);
}

advToggle.addEventListener('click', toggleAdv);
advToggle.addEventListener('keydown', function (e) {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    toggleAdv();
  }
});

// ---------- signup form ----------
var form = document.getElementById('signupForm');
var errBox = document.getElementById('signupError');

form.addEventListener('submit', function (e) {
  e.preventDefault();
  errBox.classList.remove('show');

  var payload = {
    name: document.getElementById('patientName').value,
    email: document.getElementById('patientEmail').value,
    password: pwInput.value,
  };

  submitBtn.disabled = true;
  submitBtn.textContent = 'Creating account...';

  fetch('/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
    .then(function (res) {
      return res.json().then(function (data) {
        return { status: res.ok, data: data };
      });
    })
    .then(function (result) {
      if (!result.status || !result.data.ok) {
        errBox.textContent = result.data.error || 'Something went wrong.';
        errBox.classList.add('show');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Account';
        return;
      }
      window.location.href = result.data.redirect;
    })
    .catch(function (err) {
      errBox.textContent = 'Could not reach the server. Is app.py running?';
      errBox.classList.add('show');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create Account';
    });
});

// first render, nothing typed yet
render({ score: null, policy: {}, reasons: [], hashes: {} });
