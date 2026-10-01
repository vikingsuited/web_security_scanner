const form = document.getElementById('f');
const runButton = document.getElementById('runbtn');
const consent = document.getElementById('consent');
const consentLabel = document.getElementById('consent-label');
const consentError = document.getElementById('consent-error');
const toast = document.getElementById('toast');
const activity = document.getElementById('scan-activity');
const activityLog = document.getElementById('activity-log');
const progressTrack = activity?.querySelector('.progress-track');
const reportData = document.getElementById('rd');
const tabs = [...document.querySelectorAll('.tab')];
const findings = [...document.querySelectorAll('.finding')];
const emptyState = document.getElementById('none');
let toastTimer;

function showToast(message, kind = 'error') {
  if (!toast) return;
  toast.textContent = message;
  toast.classList.toggle('toast-success', kind === 'success');
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 3600);
}

function clearConsentError() {
  consentLabel?.classList.remove('consent-invalid');
  consentError.hidden = true;
  consent?.removeAttribute('aria-invalid');
}

function validateConsent() {
  if (consent?.checked) {
    clearConsentError();
    return true;
  }
  consentLabel?.classList.add('consent-invalid');
  consentError.hidden = false;
  consent?.setAttribute('aria-invalid', 'true');
  consent?.focus();
  showToast('Permission required before scanning');
  return false;
}

function appendActivity(mark, message, pending = false) {
  if (!activityLog) return;
  const line = document.createElement('li');
  const marker = document.createElement('span');
  const text = document.createElement('span');
  line.className = `log-line${pending ? ' pending' : ''}`;
  marker.className = 'log-mark';
  marker.textContent = mark;
  text.textContent = message;
  line.append(marker, text);
  activityLog.append(line);
  activityLog.scrollTop = activityLog.scrollHeight;
}

if (consent) consent.addEventListener('change', clearConsentError);

if (form && runButton) {
  runButton.addEventListener('click', event => {
    if (!validateConsent()) event.preventDefault();
  });

  form.addEventListener('submit', event => {
    if (!validateConsent()) {
      event.preventDefault();
      return;
    }

    const selectedMode = form.querySelector('input[name="mode"]:checked');
    const target = form.querySelector('input[name="target"]').value.trim();
    runButton.disabled = true;
    runButton.querySelector('span').textContent = `SCANNING ${selectedMode?.dataset.eta || ''}`;

    if (activity) {
      activity.hidden = false;
      activity.dataset.state = 'active';
      activity.querySelector('#activity-title').textContent = 'Scan in progress';
      activity.querySelector('#activity-state-text').textContent = 'ACTIVE';
      activityLog.replaceChildren();
      progressTrack?.removeAttribute('aria-valuenow');
      appendActivity('[..]', `Submitting ${selectedMode?.value || ''} scan request for ${target}.`, true);
      setTimeout(() => appendActivity('[>>]', 'Request sent; server-side checks are running.', true), 450);
      setTimeout(() => appendActivity('[..]', 'Waiting for the completed scan report.', true), 1250);
    }
  });

  addEventListener('pageshow', () => {
    runButton.disabled = false;
    runButton.querySelector('span').textContent = 'RUN SCAN';
  });
}

tabs.forEach(tab => tab.addEventListener('click', () => {
  tabs.forEach(item => {
    const active = item === tab;
    item.classList.toggle('on', active);
    item.setAttribute('aria-pressed', String(active));
  });

  let visibleCount = 0;
  findings.forEach(finding => {
    const visible = tab.dataset.cat === 'all' || finding.dataset.cat === tab.dataset.cat;
    finding.hidden = !visible;
    if (!visible) finding.open = false;
    if (visible) visibleCount += 1;
  });

  if (emptyState) emptyState.hidden = visibleCount !== 0;
}));

if (activity?.dataset.state === 'complete') {
  activityLog?.querySelectorAll('.log-line').forEach((line, index) => {
    line.style.animationDelay = `${index * 120}ms`;
  });
  progressTrack?.setAttribute('aria-valuenow', '100');
}

const scoreRing = document.querySelector('.gauge-value');
const scoreText = document.querySelector('[data-score-value]');
if (scoreRing && scoreText) {
  const targetScore = Number(scoreRing.dataset.score) || 0;
  const circumference = Number(scoreRing.getAttribute('stroke-dasharray'));
  const finalOffset = circumference * (1 - targetScore / 100);
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) {
    scoreText.textContent = String(targetScore);
    scoreRing.style.strokeDashoffset = String(finalOffset);
  } else {
    const duration = 900;
    let startTime;
    const animateScore = timestamp => {
      startTime ??= timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      const eased = 1 - (1 - progress) ** 3;
      scoreText.textContent = String(Math.round(targetScore * eased));
      scoreRing.style.strokeDashoffset = String(circumference * (1 - targetScore * eased / 100));
      if (progress < 1) requestAnimationFrame(animateScore);
    };
    requestAnimationFrame(animateScore);
  }
}

function getReport() {
  if (!reportData) return null;
  try {
    return JSON.parse(reportData.textContent);
  } catch {
    showToast('Could not read the report data');
    return null;
  }
}

document.getElementById('copy-summary')?.addEventListener('click', async () => {
  const report = getReport();
  if (!report) return;
  const counts = Object.entries(report.summary || {})
    .filter(([, count]) => count)
    .map(([severity, count]) => `${severity}: ${count}`)
    .join(' | ') || 'No findings';
  const topFindings = (report.findings || []).slice(0, 5)
    .map(item => `- [${item.severity.toUpperCase()}] ${item.title}`).join('\n');
  const summary = [
    'Web Security Scanner Report',
    `Target: ${report.target}`,
    `Profile: ${report.mode_label}`,
    `Risk: ${report.risk_score}/100 (${report.risk_label})`,
    `Duration: ${report.duration_s}s`,
    `Findings: ${counts}`,
    topFindings ? `Top findings:\n${topFindings}` : '',
  ].filter(Boolean).join('\n');

  try {
    await navigator.clipboard.writeText(summary);
  } catch {
    const temporary = document.createElement('textarea');
    temporary.value = summary;
    temporary.setAttribute('readonly', '');
    temporary.style.position = 'fixed';
    temporary.style.opacity = '0';
    document.body.append(temporary);
    temporary.select();
    const copied = document.execCommand('copy');
    temporary.remove();
    if (!copied) {
      showToast('Clipboard access is unavailable');
      return;
    }
  }
  showToast('Summary copied to clipboard', 'success');
});

document.getElementById('export-json')?.addEventListener('click', () => {
  if (!reportData) return;
  const blobUrl = URL.createObjectURL(new Blob([reportData.textContent], {type: 'application/json'}));
  const link = Object.assign(document.createElement('a'), {href: blobUrl, download: 'scan-report.json'});
  link.click();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
});

document.getElementById('print-report')?.addEventListener('click', () => window.print());

let printDisclosureState = [];
addEventListener('beforeprint', () => {
  printDisclosureState = findings.map(finding => finding.open);
  findings.forEach(finding => { finding.open = true; });
});

addEventListener('afterprint', () => {
  findings.forEach((finding, index) => { finding.open = printDisclosureState[index] ?? false; });
});
