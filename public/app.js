/**
 * GhostProfile PRO MAX — Frontend Dashboard Controller
 */

let allProfiles = [];
let allComparisons = [];
let selectedMatrixIds = new Set();
let activeCookieProfileId = null;
let currentModalFp = null;
let toastTimer = null;

document.addEventListener('DOMContentLoaded', () => {
  bindTabs();
  bindToolbarAndModals();
  loadState();
  setInterval(loadStateSilent, 4000);
});

function showToast(msg, isError = false) {
  const el = document.getElementById('toast-box');
  if (!el) return;
  el.textContent = msg;
  el.style.borderColor = isError ? '#ef4444' : '#10b981';
  el.classList.remove('hidden');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 3600);
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function bindTabs() {
  document.querySelectorAll('.nav-tabs .tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.nav-tabs .tab-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.getAttribute('data-tab');
      document.querySelectorAll('.tab-pane').forEach((pane) => {
        pane.classList.toggle('hidden', pane.id !== `tab-${tab}`);
      });
    });
  });
}

function switchToTab(tabName) {
  const btn = document.querySelector(`.nav-tabs .tab-btn[data-tab="${tabName}"]`);
  if (btn) btn.click();
}

async function loadState() {
  try {
    const res = await fetch('/api/state').then((r) => r.json());
    if (!res.ok) return;
    allProfiles = res.profiles || [];
    allComparisons = res.comparisons || [];

    document.getElementById('stat-browser').textContent = res.browserDetected || 'Không tìm thấy';
    updateStatsAndRender();
  } catch (err) {
    console.error('Lỗi tải trạng thái:', err);
  }
}

async function loadStateSilent() {
  try {
    const res = await fetch('/api/state').then((r) => r.json());
    if (!res.ok) return;
    allProfiles = res.profiles || [];
    updateStatsAndRender();
  } catch {}
}

function updateStatsAndRender() {
  const runningCount = allProfiles.filter((p) => p.runtime?.isRunning).length;
  const verifiedCount = allProfiles.filter((p) => p.lastVerifiedReport).length;

  document.getElementById('stat-total').textContent = allProfiles.length;
  document.getElementById('stat-running').textContent = runningCount;
  document.getElementById('stat-verified').textContent = verifiedCount;
  document.getElementById('tab-count-profiles').textContent = allProfiles.length;

  renderProfilesGrid();
  renderMatrixSelectors();
  if (allComparisons.length > 0 && !document.getElementById('matrix-result-box').innerHTML.trim()) {
    renderMatrixTable(allComparisons[0]);
  }
}

function getFilteredProfiles() {
  const q = (document.getElementById('inp-search')?.value || '').trim().toLowerCase();
  const osFilter = document.getElementById('sel-filter-os')?.value || 'ALL';
  const regionFilter = document.getElementById('sel-filter-region')?.value || 'ALL';

  return allProfiles.filter((p) => {
    const fp = p.fingerprint || {};
    if (osFilter !== 'ALL' && fp.osKey !== osFilter) return false;
    if (regionFilter !== 'ALL' && fp.regionCode !== regionFilter) return false;
    if (q) {
      const hay = [
        p.name,
        p.platformTag,
        p.accountUsername,
        p.notes,
        fp.webglRenderer,
        fp.timezone,
        fp.platform
      ].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function getShortGpuName(renderer) {
  const s = String(renderer || '');
  const m = s.match(/RTX\s*\d+\s*\w*|Radeon\s*RX\s*\d+\s*\w*|Apple\s*M\d+\s*\w*|Iris\(R\)\s*Xe|UHD\s*Graphics\s*\d*/i);
  return m ? m[0] : s.slice(0, 34);
}

function getFlagEmoji(code) {
  const map = { VN: '🇻🇳', US: '🇺🇸', UK: '🇬🇧', SG: '🇸🇬', JP: '🇯🇵' };
  return map[code] || '🌍';
}

function renderProfilesGrid() {
  const container = document.getElementById('profiles-container');
  if (!container) return;

  const list = getFilteredProfiles();
  if (list.length === 0) {
    container.innerHTML = `<div class="matrix-card" style="grid-column:1/-1;text-align:center;color:var(--text-muted);">Không có Profile nào khớp bộ lọc.</div>`;
    return;
  }

  container.innerHTML = list.map((p) => {
    const fp = p.fingerprint || {};
    const rt = p.runtime || {};
    const rep = p.lastVerifiedReport;
    const warm = p.lastWarmupReport;
    const totp = p.totpLive;
    const osIcon = fp.osKey === 'macos' ? '🍎' : (fp.osKey === 'linux' ? '🐧' : '🪟');
    const flag = getFlagEmoji(fp.regionCode);
    const proxyText = p.proxy?.mode && p.proxy.mode !== 'direct'
      ? `${p.proxy.mode.toUpperCase()}://${p.proxy.host}:${p.proxy.port}`
      : `Direct (${p.proxy?.simulatedPublicIp || 'Local'})`;

    return `
      <div class="profile-card ${rt.isRunning ? 'running' : ''}" data-id="${escapeHtml(p.id)}">
        <div class="pcard-top">
          <div>
            <div class="pcard-title">${escapeHtml(p.name)}</div>
            <div class="pcard-sub">
              <span class="badge badge-tag">${escapeHtml(p.platformTag || 'Multi-Account')}</span>
              ${p.accountUsername ? `<span>👤 ${escapeHtml(p.accountUsername)}</span>` : ''}
            </div>
          </div>
          <div style="display:flex;gap:6px;align-items:center;flex-shrink:0;">
            ${rep ? `<span class="badge badge-score" title="Điểm ẩn danh thực tế">🛡️ ${rep.trustScore}/100</span>` : ''}
            ${rt.isRunning
              ? `<span class="badge badge-running">🟢 ĐANG MỞ (PID ${rt.pid})</span>`
              : `<span class="badge badge-ready">⚪ Sẵn sàng</span>`
            }
          </div>
        </div>

        <div class="fp-specs">
          <div class="fp-spec-item">
            <span class="k">Hệ Điều Hành & CPU/RAM</span>
            <span class="v">${osIcon} ${escapeHtml(fp.platform || 'Win32')} • ${fp.hardwareConcurrency || 8}C / ${fp.deviceMemory || 16}GB</span>
          </div>
          <div class="fp-spec-item">
            <span class="k">Card Đồ Họa (WebGL GPU)</span>
            <span class="v" title="${escapeHtml(fp.webglRenderer)}">🎮 ${escapeHtml(getShortGpuName(fp.webglRenderer))}</span>
          </div>
          <div class="fp-spec-item">
            <span class="k">Múi Giờ & Ngôn Ngữ</span>
            <span class="v">${flag} ${escapeHtml(fp.timezone)} (${escapeHtml(fp.locale)})</span>
          </div>
          <div class="fp-spec-item">
            <span class="k">Màn Hình & Mạng/WebRTC</span>
            <span class="v">🖥️ ${fp.screenWidth}×${fp.screenHeight} • ${escapeHtml(proxyText)}</span>
          </div>
        </div>

        <!-- 2FA TOTP Live Bar + Warmup Status -->
        <div style="display:flex;justify-content:space-between;align-items:center;background:#070c17;border:1px solid #1e293b;border-radius:9px;padding:7px 11px;gap:8px;flex-wrap:wrap;">
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="font-size:11.5px;color:#94a3b8;">🔐 Mã 2FA:</span>
            <strong style="font-family:Consolas,monospace;font-size:14px;color:#34d399;letter-spacing:1.5px;">${totp ? totp.code : '------'}</strong>
            <span style="font-size:11px;color:#fbbf24;">(${totp ? totp.remainingSec : 0}s)</span>
            <button class="btn btn-sm act-copy-totp" data-code="${totp ? totp.code : ''}" style="padding:2px 7px;font-size:11px;">📋 Copy</button>
          </div>
          <div style="display:flex;gap:6px;align-items:center;">
            ${warm ? `<span class="hash-chip" style="color:#34d399;border-color:#059669;">🍪 Đã nuôi (${warm.cookiesAfter} cookies)</span>` : ''}
            <button class="btn btn-sm act-check-proxy" data-id="${escapeHtml(p.id)}" style="padding:2px 8px;font-size:11px;" title="Kiểm tra Proxy & Tự động khớp Múi giờ/GPS">🌐 Khớp Geo</button>
          </div>
        </div>

        <div class="fp-hashes-bar">
          ${rep ? `
            <span class="hash-chip" title="Mã băm Canvas 2D thực tế">🎨 Canvas: ${escapeHtml(rep.canvasHash.slice(0, 10))}</span>
            <span class="hash-chip" title="Mã băm AudioContext thực tế">🔊 Audio: ${escapeHtml(rep.audioHash.slice(0, 10))}</span>
            <span class="hash-chip" title="Mã băm DOM ClientRects">📐 Rects: ${escapeHtml(rep.clientRectsHash.slice(0, 10))}</span>
          ` : `
            <span class="hash-chip">🎨 Canvas Seed: #${fp.canvasSeed}</span>
            <span class="hash-chip">🔊 Audio Seed: #${fp.audioSeed}</span>
            <span class="hash-chip">🔒 WebRTC: ${fp.webrtcMode === 'disable' ? 'Blocked' : 'Active'}</span>
          `}
        </div>

        ${p.notes ? `<div style="font-size:12px;color:var(--text-muted);">📝 ${escapeHtml(p.notes)}</div>` : ''}

        <div class="pcard-actions">
          <div class="pcard-actions-left">
            ${rt.isRunning
              ? `<button class="btn btn-danger btn-sm act-stop" data-id="${escapeHtml(p.id)}">⏹️ Đóng</button>`
              : `<button class="btn btn-primary btn-sm act-launch" data-id="${escapeHtml(p.id)}">🚀 Mở</button>`
            }
            <button class="btn btn-cyan btn-sm act-verify" data-id="${escapeHtml(p.id)}" title="Quét kiểm chứng 12 lớp vân tay">🔬 Quét Vân Tay</button>
            <button class="btn btn-purple btn-sm act-warmup" data-id="${escapeHtml(p.id)}" title="Chạy Cookie Robot đi dạo 3 trang & Tự điền Login + 2FA">🤖 Nuôi Cookie & 2FA</button>
            <button class="btn btn-sm act-cookies" data-id="${escapeHtml(p.id)}">🍪 Cookie</button>
          </div>
          <div class="pcard-actions-right">
            <button class="btn btn-sm act-regen" data-id="${escapeHtml(p.id)}" title="Đổi ngẫu nhiên vân tay mới">🎲</button>
            <button class="btn btn-sm act-edit" data-id="${escapeHtml(p.id)}" title="Chỉnh sửa cấu hình">✏️</button>
            <button class="btn btn-sm act-clone" data-id="${escapeHtml(p.id)}" title="Nhân bản Profile">📋</button>
            <button class="btn btn-danger btn-sm act-delete" data-id="${escapeHtml(p.id)}" title="Xóa Profile">🗑️</button>
          </div>
        </div>
      </div>
    `;
  }).join('');

  bindProfileCardEvents(container);
}

function bindProfileCardEvents(container) {
  // Copy 2FA Code
  container.querySelectorAll('.act-copy-totp').forEach((btn) => {
    btn.addEventListener('click', () => {
      const code = btn.getAttribute('data-code');
      if (code && navigator.clipboard) {
        navigator.clipboard.writeText(code);
        showToast(`🔐 Đã copy mã 2FA: ${code}`);
      }
    });
  });

  // Check Proxy & Auto-Align Geo
  container.querySelectorAll('.act-check-proxy').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-id');
      btn.disabled = true;
      btn.textContent = '⏳...';
      try {
        const res = await fetch(`/api/profiles/${id}/check-proxy`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ autoAlignGeo: true })
        }).then((r) => r.json());
        if (res.ok) {
          showToast(`🌐 IP ${res.exitIp} (${res.latencyMs}ms) → Đã đồng bộ Múi giờ ${res.alignedGeo.timezone} (${res.alignedGeo.cityName})`);
          loadState();
        }
      } finally {
        btn.disabled = false;
        btn.textContent = '🌐 Khớp Geo';
      }
    });
  });

  // Cookie Robot & Account Warmer + 2FA Auto-Fill
  container.querySelectorAll('.act-warmup').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-id');
      const orig = btn.textContent;
      btn.disabled = true;
      btn.textContent = '🤖 Đang nuôi...';
      try {
        const res = await fetch(`/api/profiles/${id}/warmup`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        }).then((r) => r.json());
        if (res.ok && res.warmupReport) {
          const w = res.warmupReport;
          showToast(`🤖 Hoàn tất nuôi Cookie (${w.sitesVisited} trang, ${w.cookiesAfter} cookies, tự điền 2FA ${w.totpUsed})!`);
          loadState();
          openWarmupReportModal(res.profile, w);
        } else {
          showToast(`❌ Lỗi Cookie Robot: ${res.error}`, true);
        }
      } catch (e) {
        showToast(`❌ Lỗi: ${e.message}`, true);
      } finally {
        btn.disabled = false;
        btn.textContent = orig;
      }
    });
  });

  // Launch visible browser
  container.querySelectorAll('.act-launch').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-id');
      btn.disabled = true;
      btn.textContent = '⏳...';
      try {
        const res = await fetch(`/api/profiles/${id}/launch`, { method: 'POST' }).then((r) => r.json());
        if (res.ok) {
          showToast(`🚀 Đã mở cửa sổ trình duyệt chống vân tay (PID ${res.pid})`);
          loadState();
        } else {
          showToast(`❌ Lỗi mở trình duyệt: ${res.error}`, true);
          btn.disabled = false;
          btn.textContent = '🚀 Mở';
        }
      } catch (e) {
        showToast(`❌ Lỗi: ${e.message}`, true);
        btn.disabled = false;
        btn.textContent = '🚀 Mở';
      }
    });
  });

  // Stop visible browser
  container.querySelectorAll('.act-stop').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-id');
      btn.disabled = true;
      await fetch(`/api/profiles/${id}/stop`, { method: 'POST' });
      showToast('⏹️ Đã đóng phiên trình duyệt.');
      loadState();
    });
  });

  // 1-Click Headless Verify Fingerprint
  container.querySelectorAll('.act-verify').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-id');
      const orig = btn.textContent;
      btn.disabled = true;
      btn.textContent = '⏳ Đang quét...';
      try {
        const res = await fetch(`/api/profiles/${id}/verify`, { method: 'POST' }).then((r) => r.json());
        if (res.ok && res.report) {
          showToast(`✅ Kiểm chứng hoàn tất: Điểm ẩn danh ${res.report.trustScore}/100`);
          loadState();
          openVerifyReportModal(res.report);
        } else {
          showToast(`❌ Lỗi kiểm chứng: ${res.error}`, true);
        }
      } catch (e) {
        showToast(`❌ Lỗi: ${e.message}`, true);
      } finally {
        btn.disabled = false;
        btn.textContent = orig;
      }
    });
  });

  // Open Cookie Vault Modal
  container.querySelectorAll('.act-cookies').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      openCookieModal(id);
    });
  });

  // Randomize Fingerprint
  container.querySelectorAll('.act-regen').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-id');
      const res = await fetch(`/api/profiles/${id}/regenerate-fp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      }).then((r) => r.json());
      if (res.ok) {
        showToast('🎲 Đã cấp phát bộ vân tay phần cứng mới!');
        loadState();
      }
    });
  });

  // Edit Profile
  container.querySelectorAll('.act-edit').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const prof = allProfiles.find((p) => p.id === id);
      if (prof) openProfileModal(prof);
    });
  });

  // Clone Profile
  container.querySelectorAll('.act-clone').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-id');
      const res = await fetch(`/api/profiles/${id}/clone`, { method: 'POST' }).then((r) => r.json());
      if (res.ok) {
        showToast('📋 Đã nhân bản Profile kèm hạt giống phần cứng mới!');
        loadState();
      }
    });
  });

  // Delete Profile
  container.querySelectorAll('.act-delete').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-id');
      await fetch(`/api/profiles/${id}`, { method: 'DELETE' });
      showToast('🗑️ Đã xóa Profile và dữ liệu cô lập.');
      loadState();
    });
  });
}

// ============================================================================
// MULTI-PROFILE FINGERPRINT COMPARISON MATRIX
// ============================================================================
function renderMatrixSelectors() {
  const box = document.getElementById('matrix-selector-list');
  if (!box) return;

  if (selectedMatrixIds.size === 0 && allProfiles.length > 0) {
    allProfiles.slice(0, Math.min(3, allProfiles.length)).forEach((p) => selectedMatrixIds.add(p.id));
  }

  box.innerHTML = allProfiles.map((p) => {
    const checked = selectedMatrixIds.has(p.id) ? 'checked' : '';
    return `
      <label style="display:inline-flex;align-items:center;gap:6px;background:#080d18;border:1px solid var(--border);padding:6px 12px;border-radius:8px;font-size:12.5px;cursor:pointer;">
        <input type="checkbox" class="chk-matrix-prof" value="${escapeHtml(p.id)}" ${checked} />
        <span>${escapeHtml(p.name)}</span>
      </label>
    `;
  }).join('');

  box.querySelectorAll('.chk-matrix-prof').forEach((chk) => {
    chk.addEventListener('change', () => {
      if (chk.checked) selectedMatrixIds.add(chk.value);
      else selectedMatrixIds.delete(chk.value);
    });
  });
}

async function runMatrixComparison() {
  const btn = document.getElementById('btn-run-matrix');
  const ids = Array.from(selectedMatrixIds);
  if (ids.length < 2) {
    showToast('⚠️ Hãy tích chọn ít nhất 2 Profile để đối chiếu sự khác biệt!', true);
    return;
  }

  btn.disabled = true;
  btn.textContent = `⏳ Đang chạy trình duyệt kiểm chứng ${ids.length} Profile...`;
  try {
    const res = await fetch('/api/profiles/compare-matrix', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profileIds: ids })
    }).then((r) => r.json());

    if (res.ok && res.matrix) {
      showToast(`✅ Đối chiếu hoàn tất ${res.matrix.totalProfiles} Profile — Độc lập 100%!`);
      renderMatrixTable(res.matrix);
      loadStateSilent();
    } else {
      showToast(`❌ Lỗi đối chiếu: ${res.error}`, true);
    }
  } catch (e) {
    showToast(`❌ Lỗi: ${e.message}`, true);
  } finally {
    btn.disabled = false;
    btn.textContent = '🚀 Chạy Kiểm Chứng & Đối Chiếu Ngay';
  }
}

function renderMatrixTable(matrix) {
  const box = document.getElementById('matrix-result-box');
  if (!box || !matrix || !Array.isArray(matrix.reports)) return;

  const reps = matrix.reports;
  const st = matrix.uniquenessStats || {};

  box.innerHTML = `
    <div class="matrix-card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">
        <div>
          <h3 style="font-size:16px;color:#34d399;">
            ${matrix.collisionFree ? '✅ KẾT QUẢ: CÁC PROFILE ĐỘC LẬP 100% (0% TRÙNG LẶP VÂN TAY)' : '⚠️ CẢNH BÁO: PHÁT HIỆN THÔNG SỐ TRÙNG'}
          </h3>
          <p style="font-size:12.5px;color:var(--text-muted);">
            Canvas 2D độc nhất: <strong>${st.canvasUnique}</strong> •
            AudioContext độc nhất: <strong>${st.audioUnique}</strong> •
            ClientRects độc nhất: <strong>${st.clientRectsUnique}</strong> •
            MediaDevices độc nhất: <strong>${st.mediaDevicesUnique}</strong>
          </p>
        </div>
        <span class="badge badge-running" style="font-size:12.5px;padding:5px 12px;">
          🛡️ Đã kiểm chứng trên nhân ${escapeHtml(reps[0]?.browserUsed || 'Chromium')}
        </span>
      </div>

      <div class="matrix-table-wrap">
        <table class="matrix-table">
          <thead>
            <tr>
              <th>Thông Số Vân Tay (Fingerprint Vector)</th>
              ${reps.map((r) => `<th>🎭 ${escapeHtml(r.profileName)}</th>`).join('')}
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Điểm Ẩn Danh & Chống Bot</strong></td>
              ${reps.map((r) => `<td style="color:#34d399;font-weight:700;">${r.trustScore}/100 (${escapeHtml(r.trustGrade)})<br/>webdriver = ${r.webdriver}</td>`).join('')}
            </tr>
            <tr>
              <td><strong>🎨 Mã Băm Canvas 2D (SHA-256)</strong></td>
              ${reps.map((r) => `<td style="color:#c4b5fd;font-weight:700;">#${escapeHtml(r.canvasHash)}</td>`).join('')}
            </tr>
            <tr>
              <td><strong>🔊 Mã Băm Sóng Âm AudioContext</strong></td>
              ${reps.map((r) => `<td style="color:#67e8f9;font-weight:700;">#${escapeHtml(r.audioHash)}</td>`).join('')}
            </tr>
            <tr>
              <td><strong>📐 Mã Băm DOM ClientRects</strong></td>
              ${reps.map((r) => `<td style="color:#fcd34d;font-weight:700;">#${escapeHtml(r.clientRectsHash)}</td>`).join('')}
            </tr>
            <tr>
              <td><strong>🎮 Card Đồ Họa WebGL & Hash</strong></td>
              ${reps.map((r) => `<td>${escapeHtml(r.webglRenderer)}<br/><span style="color:#93c5fd;">WebGL Hash: #${escapeHtml(r.webglHash)}</span></td>`).join('')}
            </tr>
            <tr>
              <td><strong>💻 Hệ Điều Hành, CPU & RAM</strong></td>
              ${reps.map((r) => `<td>${escapeHtml(r.platform)} • ${r.hardwareConcurrency} Cores • ${r.deviceMemory} GB RAM</td>`).join('')}
            </tr>
            <tr>
              <td><strong>🖥️ Độ Phân Giải Màn Hình</strong></td>
              ${reps.map((r) => `<td>${escapeHtml(r.screenResolution)}</td>`).join('')}
            </tr>
            <tr>
              <td><strong>🌍 Múi Giờ & Ngôn Ngữ</strong></td>
              ${reps.map((r) => `<td>${escapeHtml(r.timezone)}<br/>(${escapeHtml(r.languages)})</td>`).join('')}
            </tr>
            <tr>
              <td><strong>🔒 WebRTC & MediaDevices ID</strong></td>
              ${reps.map((r) => `<td>WebRTC: ${escapeHtml(r.webrtcStatus)}<br/>Devices Hash: #${escapeHtml(r.mediaDevicesHash)}</td>`).join('')}
            </tr>
            <tr>
              <td><strong>📸 Ảnh Chụp Màn Hình Thực Tế</strong></td>
              ${reps.map((r) => `<td>${r.screenshotUrl ? `<a href="${r.screenshotUrl}" target="_blank"><img src="${r.screenshotUrl}" style="width:100%;max-width:240px;border-radius:8px;border:1px solid #334155;" /></a>` : 'N/A'}</td>`).join('')}
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// ============================================================================
// MODALS & TOOLBAR HANDLERS
// ============================================================================
function bindToolbarAndModals() {
  document.getElementById('inp-search').addEventListener('input', renderProfilesGrid);
  document.getElementById('sel-filter-os').addEventListener('change', renderProfilesGrid);
  document.getElementById('sel-filter-region').addEventListener('change', renderProfilesGrid);

  document.getElementById('btn-open-create').addEventListener('click', () => openProfileModal(null));
  document.getElementById('btn-close-profile-modal').addEventListener('click', () => {
    document.getElementById('modal-profile').classList.add('hidden');
  });
  document.getElementById('btn-cancel-profile').addEventListener('click', () => {
    document.getElementById('modal-profile').classList.add('hidden');
  });

  document.getElementById('btn-quick-matrix').addEventListener('click', () => {
    switchToTab('matrix');
    runMatrixComparison();
  });

  document.getElementById('btn-run-matrix').addEventListener('click', runMatrixComparison);

  document.getElementById('btn-randomize-modal-fp').addEventListener('click', async () => {
    const osKey = document.getElementById('gen-os').value;
    const regionKey = document.getElementById('gen-region').value;
    const res = await fetch('/api/fingerprint/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ osKey, regionKey })
    }).then((r) => r.json());
    if (res.ok && res.fingerprint) {
      fillModalFingerprintFields(res.fingerprint);
      showToast('🎲 Đã sinh bộ thông số phần cứng đồng bộ!');
    }
  });

  document.getElementById('btn-save-profile').addEventListener('click', async () => {
    const editId = document.getElementById('edit-profile-id').value;
    const payload = {
      name: document.getElementById('prof-name').value.trim() || 'New Anti-Detect Profile',
      platformTag: document.getElementById('prof-platform').value.trim() || 'Multi-Account',
      accountUsername: document.getElementById('prof-username').value.trim(),
      accountPassword: document.getElementById('prof-password')?.value.trim() || '',
      totpSecret: document.getElementById('prof-totp-secret')?.value.trim() || '',
      startUrl: document.getElementById('prof-start-url').value.trim(),
      notes: document.getElementById('prof-notes').value.trim(),
      proxy: {
        mode: document.getElementById('prof-proxy-mode').value,
        host: document.getElementById('prof-proxy-host').value.trim(),
        port: document.getElementById('prof-proxy-port').value.trim()
      },
      fingerprint: {
        ...(currentModalFp || {}),
        osKey: document.getElementById('gen-os').value,
        regionCode: document.getElementById('gen-region').value,
        platform: document.getElementById('prof-fp-platform').value.trim(),
        hardwareConcurrency: Number(document.getElementById('prof-fp-cpu').value || 8),
        deviceMemory: Number(document.getElementById('prof-fp-ram').value || 16),
        screenWidth: Number(document.getElementById('prof-fp-sw').value || 1920),
        screenHeight: Number(document.getElementById('prof-fp-sh').value || 1080),
        timezone: document.getElementById('prof-fp-tz').value.trim(),
        locale: document.getElementById('prof-fp-locale').value.trim(),
        webglVendor: document.getElementById('prof-fp-vendor').value.trim(),
        webglRenderer: document.getElementById('prof-fp-renderer').value.trim(),
        webrtcMode: document.getElementById('prof-fp-webrtc').value,
        userAgent: document.getElementById('prof-fp-ua').value.trim(),
        canvasSeed: Number(document.getElementById('prof-fp-cseed').value || 123456),
        audioSeed: Number(document.getElementById('prof-fp-aseed').value || 654321),
        clientRectsSeed: Number(document.getElementById('prof-fp-rseed').value || 333444)
      }
    };

    const url = editId ? `/api/profiles/${editId}` : '/api/profiles';
    const method = editId ? 'PUT' : 'POST';
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then((r) => r.json());

    if (res.ok) {
      document.getElementById('modal-profile').classList.add('hidden');
      showToast(editId ? '💾 Đã cập nhật Profile!' : '✅ Đã tạo Profile mới thành công!');
      loadState();
    } else {
      showToast(`❌ Lỗi: ${res.error}`, true);
    }
  });

  document.getElementById('btn-submit-bulk').addEventListener('click', async () => {
    const payload = {
      prefix: document.getElementById('bulk-prefix').value.trim() || 'Account',
      count: Number(document.getElementById('bulk-count').value || 5),
      platformTag: document.getElementById('bulk-platform').value.trim(),
      osMode: document.getElementById('bulk-os').value,
      regionKey: document.getElementById('bulk-region').value,
      startUrl: document.getElementById('bulk-url').value.trim(),
      proxyListText: document.getElementById('bulk-proxies').value
    };

    const res = await fetch('/api/profiles/bulk-create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then((r) => r.json());

    if (res.ok) {
      showToast(`🏭 Đã khởi tạo thành công ${res.count} Profile độc lập!`);
      await loadState();
      switchToTab('profiles');
    } else {
      showToast(`❌ Lỗi: ${res.error}`, true);
    }
  });

  document.getElementById('btn-close-cookies-modal').addEventListener('click', () => {
    document.getElementById('modal-cookies').classList.add('hidden');
  });

  document.getElementById('btn-fill-demo-cookies').addEventListener('click', () => {
    const sample = [
      {
        name: 'c_user',
        value: '1000948271625',
        domain: 'localhost',
        path: '/',
        secure: false,
        httpOnly: false
      },
      {
        name: 'xs_session_token',
        value: 'ghost_tok_' + Date.now(),
        domain: 'localhost',
        path: '/',
        secure: false,
        httpOnly: true
      }
    ];
    document.getElementById('txt-cookies-json').value = JSON.stringify(sample, null, 2);
  });

  document.getElementById('btn-import-cookies').addEventListener('click', async () => {
    if (!activeCookieProfileId) return;
    try {
      const cookies = JSON.parse(document.getElementById('txt-cookies-json').value || '[]');
      const res = await fetch(`/api/profiles/${activeCookieProfileId}/cookies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'import', cookies })
      }).then((r) => r.json());

      if (res.ok) {
        document.getElementById('cookie-count-label').textContent = res.count;
        document.getElementById('txt-cookies-json').value = JSON.stringify(res.cookies, null, 2);
        showToast(`📥 Đã nạp Cookie vào Profile (${res.count} cookies hiện có)!`);
      }
    } catch (e) {
      showToast('❌ Định dạng JSON Cookie không hợp lệ!', true);
    }
  });

  document.getElementById('btn-clear-cookies').addEventListener('click', async () => {
    if (!activeCookieProfileId) return;
    const res = await fetch(`/api/profiles/${activeCookieProfileId}/cookies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'clear' })
    }).then((r) => r.json());
    if (res.ok) {
      document.getElementById('cookie-count-label').textContent = 0;
      document.getElementById('txt-cookies-json').value = '[]';
      showToast('🗑️ Đã xóa sạch Cookie của Profile!');
    }
  });

  document.getElementById('btn-sync-netpulse').addEventListener('click', async () => {
    if (!activeCookieProfileId) return;
    const res = await fetch(`/api/profiles/${activeCookieProfileId}/sync-netpulse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    }).then((r) => r.json());
    if (res.ok) {
      showToast(
        res.netpulseSynced
          ? '🔗 Đã đồng bộ Cookie & User-Agent sang NetPulse (4080)!'
          : 'ℹ️ Đã trích xuất Cookie & User-Agent (NetPulse 4080 hiện chưa bật).'
      );
    }
  });

  document.getElementById('btn-close-verify-modal').addEventListener('click', () => {
    document.getElementById('modal-verify').classList.add('hidden');
  });

  document.getElementById('btn-export-backup').addEventListener('click', async () => {
    const res = await fetch('/api/backup').then((r) => r.json());
    const blob = new Blob([JSON.stringify(res, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `ghostprofile-backup-${Date.now()}.json`;
    a.click();
  });

  document.getElementById('inp-import-backup').addEventListener('change', async (ev) => {
    const file = ev.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const res = await fetch('/api/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsed)
      }).then((r) => r.json());
      if (res.ok) {
        showToast(`📤 Đã khôi phục ${res.count} Profile từ bản sao lưu!`);
        loadState();
      }
    } catch {
      showToast('❌ File sao lưu không hợp lệ!', true);
    }
  });
}

async function openProfileModal(profile) {
  const modal = document.getElementById('modal-profile');
  const title = document.getElementById('modal-profile-title');
  document.getElementById('edit-profile-id').value = profile ? profile.id : '';

  if (profile) {
    title.textContent = `✏️ Chỉnh Sửa Profile: ${profile.name}`;
    document.getElementById('prof-name').value = profile.name || '';
    document.getElementById('prof-platform').value = profile.platformTag || '';
    document.getElementById('prof-username').value = profile.accountUsername || '';
    if (document.getElementById('prof-password')) {
      document.getElementById('prof-password').value = profile.accountPassword || '';
    }
    if (document.getElementById('prof-totp-secret')) {
      document.getElementById('prof-totp-secret').value = profile.totpSecret || '';
    }
    document.getElementById('prof-start-url').value = profile.startUrl || '';
    document.getElementById('prof-notes').value = profile.notes || '';
    document.getElementById('prof-proxy-mode').value = profile.proxy?.mode || 'direct';
    document.getElementById('prof-proxy-host').value = profile.proxy?.host || '';
    document.getElementById('prof-proxy-port').value = profile.proxy?.port || '';
    document.getElementById('gen-os').value = profile.fingerprint?.osKey || 'windows';
    document.getElementById('gen-region').value = profile.fingerprint?.regionCode || 'VN';
    fillModalFingerprintFields(profile.fingerprint || {});
  } else {
    title.textContent = '➕ Tạo Profile Chống Vân Tay Mới';
    document.getElementById('prof-name').value = `Profile MMO #${allProfiles.length + 1}`;
    document.getElementById('prof-platform').value = 'Facebook / TikTok';
    document.getElementById('prof-username').value = '';
    if (document.getElementById('prof-password')) document.getElementById('prof-password').value = '';
    document.getElementById('prof-start-url').value = '';
    document.getElementById('prof-notes').value = '';
    document.getElementById('prof-proxy-mode').value = 'direct';
    document.getElementById('prof-proxy-host').value = '';
    document.getElementById('prof-proxy-port').value = '';

    const res = await fetch('/api/fingerprint/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ osKey: 'windows', regionKey: 'VN' })
    }).then((r) => r.json());
    if (res.ok) {
      fillModalFingerprintFields(res.fingerprint);
      if (document.getElementById('prof-totp-secret')) {
        document.getElementById('prof-totp-secret').value = res.totpSecret || 'JBSWY3DPEHPK3PXP';
      }
    }
  }

  modal.classList.remove('hidden');
}

function fillModalFingerprintFields(fp) {
  currentModalFp = fp;
  document.getElementById('prof-fp-platform').value = fp.platform || 'Win32';
  document.getElementById('prof-fp-cpu').value = fp.hardwareConcurrency || 8;
  document.getElementById('prof-fp-ram').value = fp.deviceMemory || 16;
  document.getElementById('prof-fp-sw').value = fp.screenWidth || 1920;
  document.getElementById('prof-fp-sh').value = fp.screenHeight || 1080;
  document.getElementById('prof-fp-tz').value = fp.timezone || 'Asia/Ho_Chi_Minh';
  document.getElementById('prof-fp-locale').value = fp.locale || 'vi-VN';
  document.getElementById('prof-fp-vendor').value = fp.webglVendor || '';
  document.getElementById('prof-fp-renderer').value = fp.webglRenderer || '';
  document.getElementById('prof-fp-webrtc').value = fp.webrtcMode || 'disable';
  document.getElementById('prof-fp-ua').value = fp.userAgent || '';
  document.getElementById('prof-fp-cseed').value = fp.canvasSeed || 123456;
  document.getElementById('prof-fp-aseed').value = fp.audioSeed || 654321;
  document.getElementById('prof-fp-rseed').value = fp.clientRectsSeed || 444555;
}

async function openCookieModal(profileId) {
  activeCookieProfileId = profileId;
  const prof = allProfiles.find((p) => p.id === profileId);
  document.getElementById('modal-cookies-title').textContent = `🍪 Kho Cookie: ${prof ? prof.name : profileId}`;
  document.getElementById('txt-cookies-json').value = '// Đang đọc Cookie từ thư mục cô lập của Profile...';
  document.getElementById('modal-cookies').classList.remove('hidden');

  try {
    const res = await fetch(`/api/profiles/${profileId}/cookies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'get' })
    }).then((r) => r.json());
    if (res.ok) {
      document.getElementById('cookie-count-label').textContent = res.count;
      document.getElementById('txt-cookies-json').value = JSON.stringify(res.cookies, null, 2);
    }
  } catch (e) {
    document.getElementById('txt-cookies-json').value = '[]';
  }
}

function openVerifyReportModal(rep) {
  const modal = document.getElementById('modal-verify');
  const body = document.getElementById('modal-verify-body');
  document.getElementById('modal-verify-title').textContent = `🔬 Kết Quả Kiểm Chứng Vân Tay: ${rep.profileName}`;

  body.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
      <div class="fp-specs" style="grid-template-columns:1fr;">
        <div class="fp-spec-item"><span class="k">Điểm Ẩn Danh (Trust Score)</span><span class="v" style="color:#34d399;font-weight:700;">${rep.trustScore}/100 — ${escapeHtml(rep.trustGrade)}</span></div>
        <div class="fp-spec-item"><span class="k">Canvas 2D SHA-256</span><span class="v" style="color:#c4b5fd;">#${escapeHtml(rep.canvasHash)}</span></div>
        <div class="fp-spec-item"><span class="k">AudioContext SHA-256</span><span class="v" style="color:#67e8f9;">#${escapeHtml(rep.audioHash)}</span></div>
        <div class="fp-spec-item"><span class="k">DOM ClientRects SHA-256</span><span class="v" style="color:#fcd34d;">#${escapeHtml(rep.clientRectsHash)}</span></div>
        <div class="fp-spec-item"><span class="k">WebGL Vendor & Renderer</span><span class="v">${escapeHtml(rep.webglRenderer)}</span></div>
      </div>
      <div class="fp-specs" style="grid-template-columns:1fr;">
        <div class="fp-spec-item"><span class="k">Hệ Điều Hành & Phần Cứng</span><span class="v">${escapeHtml(rep.platform)} • ${rep.hardwareConcurrency} Cores • ${rep.deviceMemory} GB</span></div>
        <div class="fp-spec-item"><span class="k">Múi Giờ & Ngôn Ngữ</span><span class="v">${escapeHtml(rep.timezone)} (${escapeHtml(rep.languages)})</span></div>
        <div class="fp-spec-item"><span class="k">Chống Lộ WebRTC & Bot</span><span class="v">WebRTC: ${escapeHtml(rep.webrtcStatus)} • webdriver=${rep.webdriver}</span></div>
        <div class="fp-spec-item"><span class="k">Thiết Bị Media & Pin</span><span class="v">#${escapeHtml(rep.mediaDevicesHash)} • ${escapeHtml(rep.batteryInfo)}</span></div>
        <div class="fp-spec-item"><span class="k">Độ Phân Giải</span><span class="v">${escapeHtml(rep.screenResolution)}</span></div>
      </div>
    </div>
    ${rep.screenshotUrl ? `
      <div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:6px;">📸 Ảnh chụp trực tiếp từ trình duyệt của Profile khi chạy qua Phòng Lab:</div>
        <img src="${rep.screenshotUrl}" style="width:100%;border-radius:10px;border:1px solid var(--border);" />
      </div>
    ` : ''}
  `;

  modal.classList.remove('hidden');
}

function openWarmupReportModal(prof, w) {
  const modal = document.getElementById('modal-verify');
  const body = document.getElementById('modal-verify-body');
  document.getElementById('modal-verify-title').textContent = `🤖 Báo Cáo Cookie Robot & Tự Điền 2FA: ${prof.name}`;

  body.innerHTML = `
    <div class="fp-specs" style="grid-template-columns:1fr 1fr;margin-bottom:14px;">
      <div class="fp-spec-item"><span class="k">Số trang đã đi dạo</span><span class="v" style="color:#34d399;font-weight:700;">${w.sitesVisited} trang (${w.durationMs}ms)</span></div>
      <div class="fp-spec-item"><span class="k">Cookie tín nhiệm tích lũy</span><span class="v" style="color:#67e8f9;font-weight:700;">${w.cookiesBefore} → ${w.cookiesAfter} cookies</span></div>
      <div class="fp-spec-item"><span class="k">Tự động điền User + Pass + 2FA</span><span class="v" style="color:#c4b5fd;font-weight:700;">${w.autoFilled2FA ? '✅ Đã điền & Đăng nhập' : 'N/A'}</span></div>
      <div class="fp-spec-item"><span class="k">Mã 2FA TOTP đã dùng</span><span class="v" style="color:#fcd34d;font-weight:700;">${escapeHtml(w.totpUsed || '')}</span></div>
    </div>
    ${w.screenshotUrl ? `
      <div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:6px;">📸 Ảnh chụp màn hình phiên nuôi Cookie & Đăng nhập tự động 2FA:</div>
        <img src="${w.screenshotUrl}" style="width:100%;border-radius:10px;border:1px solid var(--border);" />
      </div>
    ` : ''}
  `;

  modal.classList.remove('hidden');
}
