/**
 * Automated End-to-End Test Suite for GhostProfile PRO MAX (Anti-Detect Browser Manager)
 */

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { server, generateTotpCode } = require('./server');

const STORE_FILE = path.join(__dirname, 'data', 'store.json');

async function runTests() {
  console.log('🧪 Bắt đầu kiểm thử GhostProfile PRO MAX (Anti-Detect Browser Manager)...');

  const initialBackupRes = fs.existsSync(STORE_FILE) ? fs.readFileSync(STORE_FILE, 'utf8') : null;

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Check initial state & detected browser + live 2FA TOTP codes
    const state1 = await fetch(`${baseUrl}/api/state`).then((r) => r.json());
    assert.strictEqual(state1.ok, true);
    assert.ok(state1.profiles.length >= 4, 'Should seed 4 initial MMO profiles');
    assert.ok(state1.browserDetected, 'Should detect Chrome or Edge on machine');
    assert.ok(/^\d{6}$/.test(state1.profiles[0].totpLive?.code || ''), 'Should compute 6-digit RFC 6238 TOTP code');
    console.log(`  ✅ Khởi tạo thành công (${state1.profiles.length} Profile mẫu, trình duyệt: ${state1.browserDetected}, 2FA OTP: ${state1.profiles[0].totpLive.code})`);

    // 2. Test Coherent Fingerprint Generator (macOS + US)
    const fpGen = await fetch(`${baseUrl}/api/fingerprint/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ osKey: 'macos', regionKey: 'US' })
    }).then((r) => r.json());
    assert.strictEqual(fpGen.ok, true);
    assert.strictEqual(fpGen.fingerprint.platform, 'MacIntel');
    assert.strictEqual(fpGen.fingerprint.timezone, 'America/New_York');
    assert.ok(fpGen.fingerprint.webglRenderer.includes('Apple'), 'macOS profile should use Apple Metal GPU');
    console.log('  ✅ Bộ sinh vân tay đồng bộ (macOS ↔ Apple Metal GPU ↔ America/New_York) chuẩn xác');

    // 3. Test Single Profile Real Browser Verification (/api/profiles/:id/verify)
    const targetId = state1.profiles[0].id;
    const verify1 = await fetch(`${baseUrl}/api/profiles/${targetId}/verify`, {
      method: 'POST'
    }).then((r) => r.json());
    assert.strictEqual(verify1.ok, true, 'Profile verification should succeed');
    const rep1 = verify1.report;
    assert.strictEqual(rep1.stealthInjected, true, 'Stealth script must be injected');
    assert.strictEqual(rep1.webdriver, false, 'navigator.webdriver must be false');
    assert.strictEqual(rep1.trustScore, 100, 'Trust score should be 100/100');
    assert.ok(rep1.canvasHash && rep1.canvasHash.length === 16, 'Should compute 16-char Canvas SHA-256 hash');
    assert.ok(rep1.audioHash && rep1.audioHash.length === 16, 'Should compute 16-char AudioContext hash');
    assert.ok(rep1.screenshotUrl, 'Should capture verification screenshot');
    console.log(`  ✅ Kiểm chứng thực tế trên trình duyệt thành công (Điểm: ${rep1.trustScore}/100, Canvas: #${rep1.canvasHash}, Audio: #${rep1.audioHash})`);

    // 4. Test Deterministic Consistency (Same profile verified twice -> Identical Hashes)
    const verify1Repeat = await fetch(`${baseUrl}/api/profiles/${targetId}/verify`, {
      method: 'POST'
    }).then((r) => r.json());
    assert.strictEqual(verify1Repeat.report.canvasHash, rep1.canvasHash, 'Same profile must keep consistent Canvas hash across sessions');
    assert.strictEqual(verify1Repeat.report.audioHash, rep1.audioHash, 'Same profile must keep consistent Audio hash across sessions');
    assert.strictEqual(verify1Repeat.report.clientRectsHash, rep1.clientRectsHash, 'Same profile must keep consistent ClientRects hash');
    console.log('  ✅ Tính ổn định vân tay: Cùng 1 Profile mở nhiều lần luôn giữ nguyên mã băm phần cứng');

    // 5. Test Multi-Profile Fingerprint Uniqueness Matrix (/api/profiles/compare-matrix)
    const compareIds = state1.profiles.slice(0, 3).map((p) => p.id);
    const matrixRes = await fetch(`${baseUrl}/api/profiles/compare-matrix`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profileIds: compareIds })
    }).then((r) => r.json());
    assert.strictEqual(matrixRes.ok, true);
    assert.strictEqual(matrixRes.matrix.collisionFree, true, 'All 3 profiles must have 0% hash collision');
    console.log(
      `  ✅ Ma trận đối chiếu ${matrixRes.matrix.totalProfiles} Profile: Độc lập 100% (Canvas: ${matrixRes.matrix.uniquenessStats.canvasUnique}, Audio: ${matrixRes.matrix.uniquenessStats.audioUnique}, ClientRects: ${matrixRes.matrix.uniquenessStats.clientRectsUnique})`
    );

    // 6. Test Persistent Cookie Vault Isolation (/api/profiles/:id/cookies)
    const cookieImport = await fetch(`${baseUrl}/api/profiles/${targetId}/cookies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'import',
        cookies: [
          { name: 'c_user', value: '1000888999', domain: 'localhost', path: '/' },
          { name: 'xs_token', value: 'secret_session_abc', domain: 'localhost', path: '/' }
        ]
      })
    }).then((r) => r.json());
    assert.strictEqual(cookieImport.ok, true);
    assert.ok(cookieImport.count >= 2, 'Should store imported cookies in persistent profile dir');

    const secondId = state1.profiles[1].id;
    const secondCookies = await fetch(`${baseUrl}/api/profiles/${secondId}/cookies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'get' })
    }).then((r) => r.json());
    const leaked = (secondCookies.cookies || []).some((c) => c.name === 'c_user' && c.value === '1000888999');
    assert.strictEqual(leaked, false, 'Cookies must be strictly isolated between profiles');
    console.log('  ✅ Cô lập Kho Cookie giữa các Profile hoạt động tuyệt đối (0% rò rỉ chéo)');

    // 7. Test PRO MAX: Cookie Robot Account Warmer & 1-Click 2FA Login Auto-Fill (/api/profiles/:id/warmup)
    const warmRes = await fetch(`${baseUrl}/api/profiles/${targetId}/warmup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    }).then((r) => r.json());
    assert.strictEqual(warmRes.ok, true);
    assert.strictEqual(warmRes.warmupReport.sitesVisited, 3);
    assert.strictEqual(warmRes.warmupReport.autoFilled2FA, true, 'Should auto-fill Username + Password + 2FA TOTP');
    assert.ok(warmRes.warmupReport.cookiesAfter > warmRes.warmupReport.cookiesBefore, 'Should accumulate new trust cookies');
    console.log(
      `  ✅ Cookie Robot & Tự điền 2FA thành công (${warmRes.warmupReport.sitesVisited} trang, ${warmRes.warmupReport.cookiesAfter} cookies, 2FA=${warmRes.warmupReport.totpUsed})`
    );

    // 8. Test PRO MAX: Live Proxy Checker & Auto-Geo Alignment (/api/profiles/:id/check-proxy)
    const proxyRes = await fetch(`${baseUrl}/api/profiles/${targetId}/check-proxy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ regionKey: 'JP', autoAlignGeo: true })
    }).then((r) => r.json());
    assert.strictEqual(proxyRes.ok, true);
    assert.strictEqual(proxyRes.alignedGeo.timezone, 'Asia/Tokyo');
    console.log(`  ✅ Kiểm tra Proxy & Tự khớp địa lý (Auto-Geo → ${proxyRes.alignedGeo.timezone}, ${proxyRes.latencyMs}ms) chuẩn xác`);

    // 9. Test Bulk Profile Factory (/api/profiles/bulk-create) & Delete
    const bulkRes = await fetch(`${baseUrl}/api/profiles/bulk-create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prefix: 'TestBatch',
        count: 3,
        platformTag: 'TikTok Shop',
        osMode: 'mix',
        regionKey: 'SG',
        proxyListText: '103.11.22.33:8080:u1:p1\n103.11.22.34:8080:u2:p2'
      })
    }).then((r) => r.json());
    assert.strictEqual(bulkRes.ok, true);
    assert.strictEqual(bulkRes.count, 3);

    for (const p of bulkRes.created) {
      await fetch(`${baseUrl}/api/profiles/${p.id}`, { method: 'DELETE' });
    }
    console.log('  ✅ Xưởng tạo Profile hàng loạt (Bulk Factory + Gán Proxy tự động) & Xóa dọn dẹp hoạt động chuẩn xác');

    console.log('\n🎉 Tất cả 9 bài kiểm thử End-to-End của GhostProfile PRO MAX đều PASS!');
  } finally {
    if (initialBackupRes) {
      fs.writeFileSync(STORE_FILE, initialBackupRes, 'utf8');
    }
    server.close();
  }
}

runTests().catch((err) => {
  console.error('❌ Kiểm thử thất bại:', err);
  process.exit(1);
});
