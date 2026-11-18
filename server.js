/**
 * GhostProfile PRO MAX — Anti-Detect Browser & Multi-Account Fingerprint Manager
 * 100% Local Node.js + Chrome/Edge DevTools Protocol (CDP)
 * Features:
 * - Isolated Persistent User-Data Directories per Profile
 * - 12-Layer Hardware & Browser Fingerprint Spoofing (Canvas, WebGL, AudioContext, ClientRects, WebRTC, Navigator, ClientHints, Screen, Timezone, Locale, Geolocation, MediaDevices/Battery)
 * - Built-in CreepJS / Pixelscan Style Fingerprint Verification Lab (/lab/fingerprint)
 * - Multi-Profile Uniqueness & Collision Matrix Comparator
 * - Cookie Robot & Account Warmer (/api/profiles/:id/warmup)
 * - Built-in RFC 6238 2FA TOTP Authenticator & 1-Click Auto-Fill Login (/api/profiles/:id/autofill)
 * - Live Proxy Checker & Auto-Geo Alignment (/api/profiles/:id/check-proxy)
 * - Bulk Profile Factory, Cookie Vault Import/Export & NetPulse Sync
 */

const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { URL } = require('node:url');

const PORT = Number(process.env.PORT || 4120);
const DATA_DIR = path.join(__dirname, 'data');
const PROFILES_DIR = path.join(DATA_DIR, 'profiles');
const SCREENSHOTS_DIR = path.join(DATA_DIR, 'screenshots');
const STORE_FILE = path.join(DATA_DIR, 'store.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

for (const dir of [DATA_DIR, PROFILES_DIR, SCREENSHOTS_DIR, PUBLIC_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ============================================================================
// RFC 6238 TOTP 2FA AUTHENTICATOR (BASE32 + HMAC-SHA1)
// ============================================================================
function base32ToBuffer(base32Str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = String(base32Str || '')
    .toUpperCase()
    .replace(/[^A-Z2-7]/g, '');
  if (!cleaned) return Buffer.alloc(0);

  let bits = '';
  for (let i = 0; i < cleaned.length; i++) {
    const val = alphabet.indexOf(cleaned[i]);
    if (val >= 0) bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTotpCode(secret, nowMs = Date.now(), periodSec = 30) {
  const key = base32ToBuffer(secret);
  if (!key.length) return null;

  const epochSec = Math.floor(nowMs / 1000);
  const counter = Math.floor(epochSec / periodSec);
  const remainingSec = periodSec - (epochSec % periodSec);

  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = String(binary % 1000000).padStart(6, '0');
  return {
    code: otp,
    remainingSec,
    periodSec
  };
}

function randomBase32Secret(len = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let out = '';
  for (let i = 0; i < len; i++) {
    out += chars[crypto.randomInt(0, chars.length)];
  }
  return out;
}

// ============================================================================
// COHERENT HARDWARE & GEOGRAPHIC FINGERPRINT CATALOG
// ============================================================================
const GEO_PRESETS = {
  VN: {
    countryCode: 'VN',
    countryName: 'Việt Nam',
    timezone: 'Asia/Ho_Chi_Minh',
    locale: 'vi-VN',
    languages: ['vi-VN', 'vi', 'en-US', 'en'],
    cities: [
      { name: 'Hà Nội', lat: 21.0285, lng: 105.8542 },
      { name: 'TP. Hồ Chí Minh', lat: 10.7769, lng: 106.7009 },
      { name: 'Đà Nẵng', lat: 16.0544, lng: 108.2022 }
    ]
  },
  US: {
    countryCode: 'US',
    countryName: 'United States',
    timezone: 'America/New_York',
    locale: 'en-US',
    languages: ['en-US', 'en'],
    cities: [
      { name: 'New York, NY', lat: 40.7128, lng: -74.0060 },
      { name: 'Los Angeles, CA', lat: 34.0522, lng: -118.2437 },
      { name: 'Chicago, IL', lat: 41.8781, lng: -87.6298 }
    ]
  },
  UK: {
    countryCode: 'UK',
    countryName: 'United Kingdom',
    timezone: 'Europe/London',
    locale: 'en-GB',
    languages: ['en-GB', 'en-US', 'en'],
    cities: [
      { name: 'London', lat: 51.5074, lng: -0.1278 },
      { name: 'Manchester', lat: 53.4808, lng: -2.2426 }
    ]
  },
  SG: {
    countryCode: 'SG',
    countryName: 'Singapore',
    timezone: 'Asia/Singapore',
    locale: 'en-SG',
    languages: ['en-SG', 'en-US', 'en', 'zh-SG'],
    cities: [
      { name: 'Singapore Central', lat: 1.3521, lng: 103.8198 }
    ]
  },
  JP: {
    countryCode: 'JP',
    countryName: 'Japan',
    timezone: 'Asia/Tokyo',
    locale: 'ja-JP',
    languages: ['ja-JP', 'ja', 'en-US', 'en'],
    cities: [
      { name: 'Tokyo', lat: 35.6762, lng: 139.6503 },
      { name: 'Osaka', lat: 34.6937, lng: 135.5023 }
    ]
  }
};

const HARDWARE_CATALOG = {
  windows: {
    osName: 'Windows 11 Pro (64-bit)',
    platform: 'Win32',
    chPlatform: 'Windows',
    chPlatformVersion: '15.0.0',
    userAgents: [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0'
    ],
    gpus: [
      {
        vendor: 'Google Inc. (NVIDIA)',
        renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4080 Direct3D11 vs_5_0 ps_5_0, D3D11)'
      },
      {
        vendor: 'Google Inc. (NVIDIA)',
        renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Super Direct3D11 vs_5_0 ps_5_0, D3D11)'
      },
      {
        vendor: 'Google Inc. (NVIDIA)',
        renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Ti Direct3D11 vs_5_0 ps_5_0, D3D11)'
      },
      {
        vendor: 'Google Inc. (AMD)',
        renderer: 'ANGLE (AMD, AMD Radeon RX 7800 XT Direct3D11 vs_5_0 ps_5_0, D3D11)'
      },
      {
        vendor: 'Google Inc. (Intel)',
        renderer: 'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)'
      }
    ],
    screens: [
      { width: 1920, height: 1080, scale: 1 },
      { width: 2560, height: 1440, scale: 1.25 },
      { width: 1536, height: 864, scale: 1.25 },
      { width: 1680, height: 1050, scale: 1 }
    ],
    cpuCores: [8, 12, 16, 24],
    memories: [8, 16, 32]
  },
  macos: {
    osName: 'macOS Sonoma 14.6',
    platform: 'MacIntel',
    chPlatform: 'macOS',
    chPlatformVersion: '14.6.1',
    userAgents: [
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
    ],
    gpus: [
      {
        vendor: 'Google Inc. (Apple)',
        renderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M3 Max, Unspecified Version)'
      },
      {
        vendor: 'Google Inc. (Apple)',
        renderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M3 Pro, Unspecified Version)'
      },
      {
        vendor: 'Google Inc. (Apple)',
        renderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2 Max, Unspecified Version)'
      },
      {
        vendor: 'Google Inc. (Apple)',
        renderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1 Pro, Unspecified Version)'
      }
    ],
    screens: [
      { width: 1728, height: 1117, scale: 2 },
      { width: 1512, height: 982, scale: 2 },
      { width: 1440, height: 900, scale: 2 },
      { width: 2560, height: 1440, scale: 2 }
    ],
    cpuCores: [8, 10, 12, 16],
    memories: [8, 16, 32]
  },
  linux: {
    osName: 'Ubuntu Linux 24.04 LTS',
    platform: 'Linux x86_64',
    chPlatform: 'Linux',
    chPlatformVersion: '6.8.0',
    userAgents: [
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
    ],
    gpus: [
      {
        vendor: 'Google Inc. (NVIDIA Corporation)',
        renderer: 'ANGLE (NVIDIA Corporation, NVIDIA GeForce RTX 3080/PCIe/SSE2, OpenGL 4.6.0)'
      },
      {
        vendor: 'Google Inc. (AMD)',
        renderer: 'ANGLE (AMD, Mesa Intel(R) UHD Graphics 770 (ADL-S GT1), OpenGL 4.6)'
      }
    ],
    screens: [
      { width: 1920, height: 1080, scale: 1 },
      { width: 2560, height: 1440, scale: 1 }
    ],
    cpuCores: [8, 16, 32],
    memories: [16, 32]
  }
};

function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomSeedInt(min = 100001, max = 999999) {
  return crypto.randomInt(min, max);
}

function generateCoherentFingerprint({ osKey = 'windows', regionKey = 'VN' } = {}) {
  const normalizedOs = HARDWARE_CATALOG[osKey] ? osKey : (Math.random() < 0.65 ? 'windows' : 'macos');
  const hw = HARDWARE_CATALOG[normalizedOs];
  const geo = GEO_PRESETS[regionKey] || GEO_PRESETS.VN;
  const gpu = pickRandom(hw.gpus);
  const scr = pickRandom(hw.screens);
  const city = pickRandom(geo.cities);
  const jitterLat = Number((city.lat + (Math.random() - 0.5) * 0.018).toFixed(5));
  const jitterLng = Number((city.lng + (Math.random() - 0.5) * 0.018).toFixed(5));

  return {
    osKey: normalizedOs,
    osName: hw.osName,
    platform: hw.platform,
    chPlatform: hw.chPlatform,
    chPlatformVersion: hw.chPlatformVersion,
    userAgent: pickRandom(hw.userAgents),
    hardwareConcurrency: pickRandom(hw.cpuCores),
    deviceMemory: pickRandom(hw.memories),
    screenWidth: scr.width,
    screenHeight: scr.height,
    deviceScaleFactor: scr.scale,
    colorDepth: 24,
    webglVendor: gpu.vendor,
    webglRenderer: gpu.renderer,
    canvasSeed: randomSeedInt(),
    webglSeed: randomSeedInt(),
    audioSeed: randomSeedInt(),
    clientRectsSeed: randomSeedInt(),
    mediaDevicesSeed: crypto.randomBytes(6).toString('hex'),
    webrtcMode: 'disable',
    doNotTrack: '1',
    batteryLevel: Number((0.62 + Math.random() * 0.35).toFixed(2)),
    batteryCharging: Math.random() > 0.35,
    regionCode: geo.countryCode,
    cityName: city.name,
    timezone: geo.timezone,
    locale: geo.locale,
    languages: [...geo.languages],
    latitude: jitterLat,
    longitude: jitterLng,
    accuracyMeters: crypto.randomInt(12, 45)
  };
}

// ============================================================================
// DEFAULT PROFILES & PERSISTENT STORE
// ============================================================================
function createDefaultProfiles() {
  const p1Fp = generateCoherentFingerprint({ osKey: 'macos', regionKey: 'US' });
  p1Fp.webglVendor = 'Google Inc. (Apple)';
  p1Fp.webglRenderer = 'ANGLE (Apple, ANGLE Metal Renderer: Apple M3 Max, Unspecified Version)';
  p1Fp.hardwareConcurrency = 16;
  p1Fp.deviceMemory = 32;
  p1Fp.canvasSeed = 418923;
  p1Fp.audioSeed = 782341;
  p1Fp.clientRectsSeed = 219045;

  const p2Fp = generateCoherentFingerprint({ osKey: 'windows', regionKey: 'VN' });
  p2Fp.webglVendor = 'Google Inc. (NVIDIA)';
  p2Fp.webglRenderer = 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4080 Direct3D11 vs_5_0 ps_5_0, D3D11)';
  p2Fp.hardwareConcurrency = 12;
  p2Fp.deviceMemory = 16;
  p2Fp.canvasSeed = 892317;
  p2Fp.audioSeed = 345129;
  p2Fp.clientRectsSeed = 651823;

  const p3Fp = generateCoherentFingerprint({ osKey: 'windows', regionKey: 'UK' });
  p3Fp.webglVendor = 'Google Inc. (AMD)';
  p3Fp.webglRenderer = 'ANGLE (AMD, AMD Radeon RX 7800 XT Direct3D11 vs_5_0 ps_5_0, D3D11)';
  p3Fp.hardwareConcurrency = 8;
  p3Fp.deviceMemory = 16;
  p3Fp.canvasSeed = 553912;
  p3Fp.audioSeed = 910428;
  p3Fp.clientRectsSeed = 118392;

  const p4Fp = generateCoherentFingerprint({ osKey: 'macos', regionKey: 'SG' });
  p4Fp.webglVendor = 'Google Inc. (Apple)';
  p4Fp.webglRenderer = 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2 Pro, Unspecified Version)';
  p4Fp.hardwareConcurrency = 10;
  p4Fp.deviceMemory = 16;
  p4Fp.canvasSeed = 672109;
  p4Fp.audioSeed = 194827;
  p4Fp.clientRectsSeed = 839201;

  return [
    {
      id: 'prof-fb-us-01',
      name: '📘 FB Ads Agency US #01 (Mac M3 Max)',
      platformTag: 'Facebook Ads',
      groupName: 'Team Marketing US',
      startUrl: `http://localhost:${PORT}/lab/fingerprint?profileId=prof-fb-us-01`,
      notes: 'Tài khoản BM2500 chạy camp thị trường Mỹ — IP New York',
      accountUsername: 'ads_manager_ny01@agency-us.io',
      accountPassword: 'FbAds@NY2026!Secure',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      proxy: {
        mode: 'direct',
        host: '',
        port: '',
        username: '',
        password: '',
        simulatedPublicIp: '198.51.100.42'
      },
      fingerprint: p1Fp,
      lastVerifiedReport: null,
      lastWarmupReport: null,
      lastLaunchAt: null,
      createdAt: new Date(Date.now() - 86400000 * 4).toISOString()
    },
    {
      id: 'prof-shopee-vn-02',
      name: '🛒 Shopee Mall Flagship VN #02 (RTX 4080)',
      platformTag: 'Shopee / TikTok VN',
      groupName: 'Team E-Commerce VN',
      startUrl: `http://localhost:${PORT}/lab/fingerprint?profileId=prof-shopee-vn-02`,
      notes: 'Gian hàng chính hãng Hà Nội — Không dùng chung IP với shop phụ',
      accountUsername: 'shop_flagship_hn@vnmall.vn',
      accountPassword: 'ShopeeMall#2026VN',
      totpSecret: 'GEZDGNBVGY3TQOJQ',
      proxy: {
        mode: 'direct',
        host: '',
        port: '',
        username: '',
        password: '',
        simulatedPublicIp: '113.190.232.88'
      },
      fingerprint: p2Fp,
      lastVerifiedReport: null,
      lastWarmupReport: null,
      lastLaunchAt: null,
      createdAt: new Date(Date.now() - 86400000 * 3).toISOString()
    },
    {
      id: 'prof-tiktok-uk-03',
      name: '🎵 TikTok Creator Shop UK #03 (RX 7800 XT)',
      platformTag: 'TikTok Global',
      groupName: 'Team Creator UK',
      startUrl: `http://localhost:${PORT}/lab/fingerprint?profileId=prof-tiktok-uk-03`,
      notes: 'Kênh Affiliate thị trường Anh Quốc — Múi giờ London',
      accountUsername: 'uk_trend_daily@creator.co.uk',
      accountPassword: 'TikTokUK$9988',
      totpSecret: 'MFRGGZDFMZTWQ2LK',
      proxy: {
        mode: 'direct',
        host: '',
        port: '',
        username: '',
        password: '',
        simulatedPublicIp: '81.2.69.142'
      },
      fingerprint: p3Fp,
      lastVerifiedReport: null,
      lastWarmupReport: null,
      lastLaunchAt: null,
      createdAt: new Date(Date.now() - 86400000 * 2).toISOString()
    },
    {
      id: 'prof-airdrop-sg-04',
      name: '💎 Web3 & Crypto Airdrop SG #04 (Mac M2 Pro)',
      platformTag: 'Crypto / Web3',
      groupName: 'Team Airdrop Hunt',
      startUrl: `http://localhost:${PORT}/lab/fingerprint?profileId=prof-airdrop-sg-04`,
      notes: 'Ví MetaMask + Rabby săn Airdrop Layer2 — Múi giờ Singapore',
      accountUsername: '0x71C...89A4 (Whale #04)',
      accountPassword: 'VaultWeb3#SG2026',
      totpSecret: 'KRSXG5CTMVRXEZLU',
      proxy: {
        mode: 'direct',
        host: '',
        port: '',
        username: '',
        password: '',
        simulatedPublicIp: '175.41.148.99'
      },
      fingerprint: p4Fp,
      lastVerifiedReport: null,
      lastWarmupReport: null,
      lastLaunchAt: null,
      createdAt: new Date(Date.now() - 86400000).toISOString()
    }
  ];
}

let store = {
  profiles: createDefaultProfiles(),
  comparisons: []
};

function loadStore() {
  try {
    if (fs.existsSync(STORE_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
      if (parsed && Array.isArray(parsed.profiles) && parsed.profiles.length > 0) {
        store = {
          profiles: parsed.profiles.map((p, i) => ({
            ...p,
            accountPassword: p.accountPassword || `Pass#${1000 + i}`,
            totpSecret: p.totpSecret || randomBase32Secret(16)
          })),
          comparisons: Array.isArray(parsed.comparisons) ? parsed.comparisons.slice(0, 25) : []
        };
      }
    }
  } catch (err) {
    console.error('[GhostProfile Store] Load error:', err.message);
  }
}

function saveStore() {
  try {
    fs.writeFileSync(STORE_FILE, JSON.stringify(store, null, 2), 'utf8');
  } catch (err) {
    console.error('[GhostProfile Store] Save error:', err.message);
  }
}

loadStore();

function pruneOldScreenshots(maxFiles = 30) {
  try {
    const files = fs.readdirSync(SCREENSHOTS_DIR)
      .filter((f) => f.endsWith('.png'))
      .map((name) => {
        const full = path.join(SCREENSHOTS_DIR, name);
        return { name, full, mtime: fs.statSync(full).mtimeMs };
      })
      .sort((a, b) => b.mtime - a.mtime);
    for (const old of files.slice(maxFiles)) {
      try { fs.unlinkSync(old.full); } catch {}
    }
  } catch {}
}

// ============================================================================
// 12-LAYER ANTI-DETECT JAVASCRIPT INJECTION BUILDER
// ============================================================================
function buildStealthInjectionScript(profile) {
  const fp = profile.fingerprint || {};
  const payload = {
    profileId: profile.id,
    profileName: profile.name,
    platform: fp.platform || 'Win32',
    chPlatform: fp.chPlatform || 'Windows',
    chPlatformVersion: fp.chPlatformVersion || '15.0.0',
    userAgent: fp.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    hardwareConcurrency: Number(fp.hardwareConcurrency || 8),
    deviceMemory: Number(fp.deviceMemory || 16),
    screenWidth: Number(fp.screenWidth || 1920),
    screenHeight: Number(fp.screenHeight || 1080),
    deviceScaleFactor: Number(fp.deviceScaleFactor || 1),
    colorDepth: Number(fp.colorDepth || 24),
    webglVendor: fp.webglVendor || 'Google Inc. (NVIDIA)',
    webglRenderer: fp.webglRenderer || 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4080 Direct3D11 vs_5_0 ps_5_0, D3D11)',
    canvasSeed: Number(fp.canvasSeed || 123456),
    webglSeed: Number(fp.webglSeed || 654321),
    audioSeed: Number(fp.audioSeed || 333777),
    clientRectsSeed: Number(fp.clientRectsSeed || 444888),
    mediaDevicesSeed: String(fp.mediaDevicesSeed || 'a1b2c3d4e5f6'),
    webrtcMode: fp.webrtcMode || 'disable',
    simulatedIp: profile.proxy?.simulatedPublicIp || '198.51.100.25',
    doNotTrack: String(fp.doNotTrack ?? '1'),
    batteryLevel: Number(fp.batteryLevel || 0.85),
    batteryCharging: Boolean(fp.batteryCharging ?? true),
    timezone: fp.timezone || 'Asia/Ho_Chi_Minh',
    locale: fp.locale || 'vi-VN',
    languages: Array.isArray(fp.languages) && fp.languages.length ? fp.languages : ['vi-VN', 'vi', 'en-US', 'en'],
    latitude: Number(fp.latitude ?? 21.0285),
    longitude: Number(fp.longitude ?? 105.8542),
    accuracyMeters: Number(fp.accuracyMeters || 20)
  };

  return `
(function() {
  if (window.__GHOST_PROFILE_INJECTED__) return;
  const CFG = ${JSON.stringify(payload)};
  Object.defineProperty(window, '__GHOST_PROFILE_INJECTED__', { value: true, configurable: false, enumerable: false });
  Object.defineProperty(window, '__GHOST_PROFILE_CFG__', { value: CFG, configurable: false, enumerable: false });

  // 1. Remove navigator.webdriver & Automation Markers
  try {
    Object.defineProperty(Navigator.prototype, 'webdriver', {
      get: function() { return false; },
      configurable: true,
      enumerable: true
    });
  } catch (e) {}

  // 2. Spoof Navigator Properties (Platform, CPU, RAM, Languages, DoNotTrack)
  const navOverrides = {
    userAgent: CFG.userAgent,
    appVersion: CFG.userAgent.replace(/^Mozilla\\//, ''),
    platform: CFG.platform,
    hardwareConcurrency: CFG.hardwareConcurrency,
    deviceMemory: CFG.deviceMemory,
    language: CFG.languages[0] || CFG.locale,
    languages: Object.freeze([...CFG.languages]),
    doNotTrack: CFG.doNotTrack,
    maxTouchPoints: 0,
    pdfViewerEnabled: true,
    vendor: 'Google Inc.'
  };
  for (const [prop, val] of Object.entries(navOverrides)) {
    try {
      Object.defineProperty(Navigator.prototype, prop, {
        get: function() { return val; },
        configurable: true,
        enumerable: true
      });
    } catch (e) {}
  }

  // 3. Spoof Sec-CH-UA UserAgentData
  try {
    const fakeUAData = {
      brands: [
        { brand: 'Chromium', version: '131' },
        { brand: 'Google Chrome', version: '131' },
        { brand: 'Not_A Brand', version: '24' }
      ],
      mobile: false,
      platform: CFG.chPlatform,
      getHighEntropyValues: async function(hints) {
        return {
          architecture: 'x86',
          bitness: '64',
          brands: this.brands,
          fullVersionList: [
            { brand: 'Chromium', version: '131.0.6778.86' },
            { brand: 'Google Chrome', version: '131.0.6778.86' },
            { brand: 'Not_A Brand', version: '24.0.0.0' }
          ],
          mobile: false,
          model: '',
          platform: CFG.chPlatform,
          platformVersion: CFG.chPlatformVersion,
          uaFullVersion: '131.0.6778.86'
        };
      },
      toJSON: function() {
        return { brands: this.brands, mobile: this.mobile, platform: this.platform };
      }
    };
    Object.defineProperty(Navigator.prototype, 'userAgentData', {
      get: function() { return fakeUAData; },
      configurable: true
    });
  } catch (e) {}

  // 4. Spoof Screen & DevicePixelRatio
  try {
    const screenProps = {
      width: CFG.screenWidth,
      height: CFG.screenHeight,
      availWidth: CFG.screenWidth,
      availHeight: CFG.screenHeight - 40,
      colorDepth: CFG.colorDepth,
      pixelDepth: CFG.colorDepth
    };
    for (const [k, v] of Object.entries(screenProps)) {
      Object.defineProperty(Screen.prototype, k, {
        get: function() { return v; },
        configurable: true
      });
    }
    Object.defineProperty(window, 'devicePixelRatio', {
      get: function() { return CFG.deviceScaleFactor; },
      configurable: true
    });
  } catch (e) {}

  // 5. Deterministic Canvas 2D Fingerprint Perturbation (Xorshift32 PRNG)
  try {
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    const applyCanvasNoise = function(imgData) {
      const data = imgData.data;
      const len = data.length;
      if (len >= 64) {
        let x = (CFG.canvasSeed || 123456789) >>> 0;
        const limit = Math.min(len, 1600);
        for (let i = 0; i < limit; i += 4) {
          x ^= x << 13;
          x ^= x >>> 17;
          x ^= x << 5;
          const ch = (x >>> 0) % 3;
          const shift = ((x >>> 4) & 3) + 1;
          const val = data[i + ch];
          data[i + ch] = val < 240 ? val + shift : val - shift;
        }
      }
      return imgData;
    };

    CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
      const imgData = origGetImageData.call(this, sx, sy, sw, sh);
      return applyCanvasNoise(imgData);
    };

    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
      try {
        const ctx = this.getContext('2d');
        if (ctx && this.width > 0 && this.height > 0) {
          const w = Math.min(this.width, 32);
          const h = Math.min(this.height, 32);
          const img = origGetImageData.call(ctx, 0, 0, w, h);
          applyCanvasNoise(img);
          ctx.putImageData(img, 0, 0);
        }
      } catch (e) {}
      return origToDataURL.apply(this, args);
    };
  } catch (e) {}

  // 6. WebGL Vendor, Renderer & Parameter Spoofing
  try {
    const patchWebGL = function(proto) {
      if (!proto || !proto.getParameter) return;
      const origGetParameter = proto.getParameter;
      proto.getParameter = function(param) {
        if (param === 37445) return CFG.webglVendor;   // UNMASKED_VENDOR_WEBGL
        if (param === 37446) return CFG.webglRenderer; // UNMASKED_RENDERER_WEBGL
        if (param === 7936) return 'WebKit';           // VENDOR
        if (param === 7937) return 'WebKit WebGL';     // RENDERER
        return origGetParameter.call(this, param);
      };
      const origGetExtension = proto.getExtension;
      proto.getExtension = function(name) {
        if (name === 'WEBGL_debug_renderer_info') {
          return origGetExtension.call(this, name) || {
            UNMASKED_VENDOR_WEBGL: 37445,
            UNMASKED_RENDERER_WEBGL: 37446
          };
        }
        return origGetExtension.call(this, name);
      };
    };
    if (typeof WebGLRenderingContext !== 'undefined') patchWebGL(WebGLRenderingContext.prototype);
    if (typeof WebGL2RenderingContext !== 'undefined') patchWebGL(WebGL2RenderingContext.prototype);
  } catch (e) {}

  // 7. Deterministic AudioContext Fingerprint Perturbation (All samples)
  try {
    if (typeof AudioBuffer !== 'undefined') {
      const origGetChannelData = AudioBuffer.prototype.getChannelData;
      AudioBuffer.prototype.getChannelData = function(channel) {
        const arr = origGetChannelData.call(this, channel);
        if (!arr.__ghostPatched && arr.length > 0) {
          let x = (CFG.audioSeed || 987654321) >>> 0;
          for (let i = 0; i < arr.length; i++) {
            x ^= x << 13;
            x ^= x >>> 17;
            x ^= x << 5;
            const micro = (((x >>> 0) % 199) - 99) * 1e-7;
            arr[i] = arr[i] + micro;
          }
          Object.defineProperty(arr, '__ghostPatched', { value: true, enumerable: false });
        }
        return arr;
      };
    }
  } catch (e) {}

  // 8. ClientRects Sub-Pixel Noise
  try {
    const origGetBoundingClientRect = Element.prototype.getBoundingClientRect;
    const seedVal = Number(CFG.clientRectsSeed || 444888);
    const jx = ((seedVal % 997) + 13) * 1e-5;
    const jy = (((seedVal * 7) % 991) + 17) * 1e-5;
    Element.prototype.getBoundingClientRect = function() {
      const r = origGetBoundingClientRect.call(this);
      return new DOMRect(
        r.x + jx,
        r.y + jy,
        r.width + jx,
        r.height + jy
      );
    };
  } catch (e) {}

  // 9. WebRTC IP Leak Protection
  try {
    if (CFG.webrtcMode === 'disable') {
      const BlockedRTC = function() {
        throw new DOMException('WebRTC is disabled by GhostProfile Anti-Detect Policy', 'NotAllowedError');
      };
      window.RTCPeerConnection = BlockedRTC;
      window.webkitRTCPeerConnection = BlockedRTC;
    }
  } catch (e) {}

  // 10. MediaDevices Deterministic Device IDs
  try {
    if (navigator.mediaDevices) {
      const s = CFG.mediaDevicesSeed;
      navigator.mediaDevices.enumerateDevices = async function() {
        return [
          { deviceId: 'default', kind: 'audioinput', label: '', groupId: 'grp_ain_' + s },
          { deviceId: 'mic_' + s + '01', kind: 'audioinput', label: '', groupId: 'grp_ain_' + s },
          { deviceId: 'cam_' + s + '02', kind: 'videoinput', label: '', groupId: 'grp_vin_' + s },
          { deviceId: 'spk_' + s + '03', kind: 'audiooutput', label: '', groupId: 'grp_aout_' + s }
        ];
      };
    }
  } catch (e) {}

  // 11. Battery API Spoofing
  try {
    Navigator.prototype.getBattery = async function() {
      return {
        charging: CFG.batteryCharging,
        chargingTime: CFG.batteryCharging ? 1800 : Infinity,
        dischargingTime: CFG.batteryCharging ? Infinity : 14400,
        level: CFG.batteryLevel,
        onchargingchange: null,
        onchargingtimechange: null,
        ondischargingtimechange: null,
        onlevelchange: null
      };
    };
  } catch (e) {}

  // 12. Geolocation Override
  try {
    if (navigator.geolocation) {
      const fakePos = {
        coords: {
          latitude: CFG.latitude,
          longitude: CFG.longitude,
          accuracy: CFG.accuracyMeters,
          altitude: null,
          altitudeAccuracy: null,
          heading: null,
          speed: null
        },
        timestamp: Date.now()
      };
      navigator.geolocation.getCurrentPosition = function(success) {
        if (typeof success === 'function') setTimeout(() => success(fakePos), 15);
      };
      navigator.geolocation.watchPosition = function(success) {
        if (typeof success === 'function') setTimeout(() => success(fakePos), 15);
        return 1;
      };
    }
  } catch (e) {}
})();
`;
}

// ============================================================================
// BUILT-IN WARMUP SANDBOX & LOGIN PORTAL (/warmup/:stage)
// ============================================================================
function renderWarmupStageHtml(stage, profileId) {
  const titles = {
    search: '🔎 OmniSearch Portal — Tìm kiếm & Tích lũy Cookie Tín nhiệm (Bước 1/3)',
    news: '📰 DailyTech News — Đọc Báo & Cuộn Trang Tự Nhiên (Bước 2/3)',
    marketplace: '🛒 Global Commerce & 2FA Login Sandbox (Bước 3/3)'
  };
  const title = titles[stage] || titles.marketplace;

  return `<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>${title}</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #090e1a; color: #f8fafc; padding: 28px; }
    .box { max-width: 860px; margin: 0 auto; background: #111a2e; border: 1px solid #1e293b; border-radius: 14px; padding: 24px; }
    h1 { color: #34d399; font-size: 20px; margin-bottom: 8px; }
    p { color: #94a3b8; font-size: 13.5px; margin-bottom: 14px; }
    .article { background: #0b1220; border: 1px solid #1e293b; padding: 14px; border-radius: 10px; margin-bottom: 12px; }
    .login-card { background: #0b1220; border: 1px solid #10b981; padding: 18px; border-radius: 12px; margin-top: 16px; }
    label { display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px; margin-top: 10px; }
    input { width: 100%; padding: 9px 12px; border-radius: 8px; border: 1px solid #334155; background: #060a12; color: #fff; font-size: 13.5px; }
    button { margin-top: 14px; padding: 10px 18px; background: #10b981; color: #04130d; font-weight: 700; border: none; border-radius: 8px; cursor: pointer; }
    #login-status { margin-top: 12px; font-weight: 700; color: #38bdf8; }
  </style>
</head>
<body>
  <div class="box">
    <h1>${title}</h1>
    <p>Profile đang hoạt động: <strong>${profileId || 'GhostProfile'}</strong> • Đã cấp phát Trust Cookie tự động.</p>

    <div class="article">
      <h3>📌 Nội dung mô phỏng hành vi người dùng thật #1</h3>
      <p>Cookie Robot tự động cuộn trang, di chuột và lưu trữ phiên duyệt web hợp lệ vào thư mục cô lập của Profile.</p>
    </div>

    <div class="login-card">
      <h3 style="color:#38bdf8;">🔐 Cổng Đăng Nhập & Xác Thực 2FA (Hỗ trợ Auto-Fill 1-Click)</h3>
      <label>Tài khoản / Email (Username)</label>
      <input type="text" id="login-username" name="username" placeholder="Nhập username hoặc bấm Tự Điền 1-Click..." />
      <label>Mật khẩu (Password)</label>
      <input type="password" id="login-password" name="password" placeholder="Nhập mật khẩu..." />
      <label>Mã xác thực 2FA 6 số (TOTP Authenticator)</label>
      <input type="text" id="login-totp" name="totp" placeholder="Mã 6 số (VD: 482910)" />
      <button id="btn-login-submit" onclick="document.getElementById('login-status').textContent='✅ ĐĂNG NHẬP & XÁC THỰC 2FA THÀNH CÔNG: ' + document.getElementById('login-username').value">🚀 Đăng Nhập Tài Khoản</button>
      <div id="login-status"></div>
    </div>

    <div style="height: 450px; margin-top: 20px; border-top: 1px dashed #1e293b; padding-top: 16px; color: #64748b;">
      Vùng cuộn trang tự nhiên (Human Scroll Area) — Cookie Robot sẽ cuộn tới cuối trang này.
    </div>
  </div>
</body>
</html>`;
}

// ============================================================================
// BUILT-IN FINGERPRINT SCANNER LABORATORY HTML (/lab/fingerprint)
// ============================================================================
function renderFingerprintLabHtml(profileId) {
  const profile = store.profiles.find((p) => p.id === profileId) || null;
  const profileTitle = profile ? profile.name : 'Trình Duyệt Hiện Tại';

  return `<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>🔬 GhostProfile Lab — Kiểm Chứng Vân Tay Phần Cứng (${profileTitle})</title>
  <style>
    :root {
      --bg: #070b14;
      --card: #0f172a;
      --border: #1e293b;
      --accent: #10b981;
      --cyan: #06b6d4;
      --purple: #8b5cf6;
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: radial-gradient(circle at top right, #0f292e 0%, var(--bg) 55%);
      color: var(--text);
      padding: 24px;
      min-height: 100vh;
    }
    .container { max-width: 1120px; margin: 0 auto; }
    .hero {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: linear-gradient(135deg, rgba(16,185,129,0.14), rgba(6,182,212,0.08));
      border: 1px solid rgba(16,185,129,0.35);
      border-radius: 16px;
      padding: 20px 24px;
      margin-bottom: 20px;
    }
    .hero h1 { font-size: 21px; margin-bottom: 6px; color: #34d399; }
    .hero p { font-size: 13.5px; color: var(--muted); }
    .score-box {
      text-align: center;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(52, 211, 153, 0.45);
      border-radius: 14px;
      padding: 12px 22px;
      min-width: 170px;
    }
    .score-val { font-size: 28px; font-weight: 900; color: #34d399; }
    .score-lbl { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(330px, 1fr));
      gap: 16px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px 18px;
    }
    .card h3 {
      font-size: 14px;
      color: #38bdf8;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid rgba(255,255,255,0.06);
      padding-bottom: 8px;
    }
    .row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      font-size: 12.5px;
      padding: 6px 0;
      border-bottom: 1px dashed rgba(255,255,255,0.05);
    }
    .row:last-child { border-bottom: none; }
    .lbl { color: var(--muted); flex-shrink: 0; }
    .val {
      color: var(--text);
      font-family: 'Consolas', monospace;
      text-align: right;
      word-break: break-all;
    }
    .hash-pill {
      display: inline-block;
      background: rgba(139, 92, 246, 0.18);
      color: #c4b5fd;
      border: 1px solid rgba(139, 92, 246, 0.4);
      padding: 2px 8px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 12px;
    }
    .pass-pill {
      background: rgba(16, 185, 129, 0.18);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.4);
      padding: 2px 8px;
      border-radius: 99px;
      font-size: 11px;
      font-weight: 700;
    }
    canvas#demo-canvas {
      width: 100%;
      height: 64px;
      border-radius: 8px;
      border: 1px solid #334155;
      margin-bottom: 8px;
      background: #090d16;
    }
    #client-rect-probe {
      position: absolute;
      left: -9999px;
      top: -9999px;
      font-size: 17.35px;
      font-family: Georgia, serif;
      padding: 3.14px 7.89px;
    }
  </style>
</head>
<body>
  <div id="client-rect-probe">GhostProfile Sub-Pixel DOM Probe 1234567890</div>
  <div class="container">
    <div class="hero">
      <div>
        <h1>🎭 Phòng Thí Nghiệm Kiểm Chứng Vân Tay (GhostProfile Lab)</h1>
        <p id="lab-subtitle">Đang phân tích chữ ký phần cứng thực tế từ DOM, Canvas 2D, WebGL, AudioContext & WebRTC...</p>
      </div>
      <div class="score-box">
        <div class="score-val" id="trust-score">...</div>
        <div class="score-lbl" id="trust-grade">ĐANG QUÉT</div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h3><span>🎨 1. Chữ Ký Đồ Họa Canvas 2D & ClientRects</span><span class="pass-pill">NOISE ACTIVE</span></h3>
        <canvas id="demo-canvas" width="320" height="64"></canvas>
        <div class="row"><span class="lbl">Canvas 2D SHA-256:</span><span class="val"><span class="hash-pill" id="out-canvas-hash">...</span></span></div>
        <div class="row"><span class="lbl">DOM ClientRects Hash:</span><span class="val"><span class="hash-pill" id="out-rects-hash">...</span></span></div>
        <div class="row"><span class="lbl">Độ phân giải & Tỷ lệ:</span><span class="val" id="out-screen">...</span></div>
      </div>

      <div class="card">
        <h3><span>🎮 2. Card Đồ Họa WebGL & Audio Oscillator</span><span class="pass-pill">SPOOFED</span></h3>
        <div class="row"><span class="lbl">WebGL Unmasked Vendor:</span><span class="val" id="out-webgl-vendor">...</span></div>
        <div class="row"><span class="lbl">WebGL Unmasked Renderer:</span><span class="val" id="out-webgl-renderer">...</span></div>
        <div class="row"><span class="lbl">WebGL Parameter Hash:</span><span class="val"><span class="hash-pill" id="out-webgl-hash">...</span></span></div>
        <div class="row"><span class="lbl">AudioContext Hash:</span><span class="val"><span class="hash-pill" id="out-audio-hash">...</span></span></div>
      </div>

      <div class="card">
        <h3><span>💻 3. Hệ Điều Hành, CPU, RAM & Chống Bot</span><span class="pass-pill" id="out-bot-badge">STEALTH</span></h3>
        <div class="row"><span class="lbl">navigator.webdriver:</span><span class="val" id="out-webdriver">...</span></div>
        <div class="row"><span class="lbl">Platform / OS:</span><span class="val" id="out-platform">...</span></div>
        <div class="row"><span class="lbl">CPU Cores / RAM:</span><span class="val" id="out-hw">...</span></div>
        <div class="row"><span class="lbl">User-Agent:</span><span class="val" id="out-ua">...</span></div>
      </div>

      <div class="card">
        <h3><span>🌍 4. Múi Giờ, Ngôn Ngữ, WebRTC & Thiết Bị</span><span class="pass-pill">ISOLATED</span></h3>
        <div class="row"><span class="lbl">Múi giờ (Intl Timezone):</span><span class="val" id="out-tz">...</span></div>
        <div class="row"><span class="lbl">Ngôn ngữ (Languages):</span><span class="val" id="out-lang">...</span></div>
        <div class="row"><span class="lbl">Trạng thái WebRTC Leak:</span><span class="val" id="out-webrtc">...</span></div>
        <div class="row"><span class="lbl">MediaDevices & Pin:</span><span class="val" id="out-devices">...</span></div>
      </div>
    </div>
  </div>

  <script>
    async function sha256Short(str) {
      const buf = new TextEncoder().encode(String(str));
      const digest = await crypto.subtle.digest('SHA-256', buf);
      const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
      return hex.slice(0, 16).toUpperCase();
    }

    async function computeCanvasFingerprint() {
      const canvas = document.getElementById('demo-canvas');
      const ctx = canvas.getContext('2d');
      const grad = ctx.createLinearGradient(0, 0, 320, 64);
      grad.addColorStop(0, '#0f172a');
      grad.addColorStop(0.5, '#1e3a8a');
      grad.addColorStop(1, '#065f46');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 320, 64);

      ctx.fillStyle = '#38bdf8';
      ctx.font = 'bold 16px Arial';
      ctx.fillText('GhostProfile Anti-Detect 🎭 #2026', 14, 28);

      ctx.fillStyle = '#f43f5e';
      ctx.font = '13px Georgia';
      ctx.fillText('Cwm fjordbank glyphs vext quiz, 😃🔒', 14, 50);

      ctx.strokeStyle = '#fbbf24';
      ctx.beginPath();
      ctx.arc(275, 32, 20, 0, Math.PI * 1.75);
      ctx.stroke();

      const dataUrl = canvas.toDataURL('image/png');
      return await sha256Short(dataUrl);
    }

    async function computeWebglFingerprint() {
      const c = document.createElement('canvas');
      const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { vendor: 'N/A', renderer: 'N/A', hash: 'NO_WEBGL' };
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      const sig = [
        vendor,
        renderer,
        gl.getParameter(gl.VERSION),
        gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        gl.getParameter(gl.MAX_TEXTURE_SIZE)
      ].join('|');
      return {
        vendor: String(vendor || ''),
        renderer: String(renderer || ''),
        hash: await sha256Short(sig)
      };
    }

    async function computeAudioFingerprint() {
      try {
        const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!OfflineCtx) return 'UNSUPPORTED';
        const context = new OfflineCtx(1, 4096, 44100);
        const oscillator = context.createOscillator();
        oscillator.type = 'triangle';
        oscillator.frequency.setValueAtTime(10000, context.currentTime);

        const compressor = context.createDynamicsCompressor();
        compressor.threshold.setValueAtTime(-50, context.currentTime);
        compressor.knee.setValueAtTime(40, context.currentTime);
        compressor.ratio.setValueAtTime(12, context.currentTime);
        compressor.attack.setValueAtTime(0, context.currentTime);
        compressor.release.setValueAtTime(0.25, context.currentTime);

        oscillator.connect(compressor);
        compressor.connect(context.destination);
        oscillator.start(0);

        const renderedBuffer = await context.startRendering();
        const data = renderedBuffer.getChannelData(0);
        let sum = '';
        for (let i = 450; i < 650; i += 4) {
          sum += data[i].toFixed(9) + ',';
        }
        return await sha256Short(sum);
      } catch (e) {
        return 'ERR_' + e.message.slice(0, 8);
      }
    }

    async function computeClientRectsFingerprint() {
      const el = document.getElementById('client-rect-probe');
      const r = el.getBoundingClientRect();
      const raw = [r.x, r.y, r.width, r.height, r.top, r.left, r.right, r.bottom].map(n => Number(n).toFixed(7)).join('|');
      return await sha256Short(raw);
    }

    async function checkWebRtcStatus() {
      if (typeof window.RTCPeerConnection === 'undefined') {
        return 'BLOCKED (An toàn 100%)';
      }
      try {
        const pc = new window.RTCPeerConnection({ iceServers: [] });
        pc.close();
        return 'ACTIVE';
      } catch (e) {
        return 'BLOCKED (' + e.name + ')';
      }
    }

    async function runFullScan() {
      const canvasHash = await computeCanvasFingerprint();
      const webgl = await computeWebglFingerprint();
      const audioHash = await computeAudioFingerprint();
      const clientRectsHash = await computeClientRectsFingerprint();
      const webrtcStatus = await checkWebRtcStatus();

      let mediaDevicesHash = 'NONE';
      let deviceCount = 0;
      try {
        if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
          const devs = await navigator.mediaDevices.enumerateDevices();
          deviceCount = devs.length;
          mediaDevicesHash = await sha256Short(devs.map(d => d.kind + ':' + d.deviceId + ':' + d.groupId).join('|'));
        }
      } catch (e) {}

      let batteryInfo = 'N/A';
      try {
        if (navigator.getBattery) {
          const b = await navigator.getBattery();
          batteryInfo = Math.round(b.level * 100) + '% (' + (b.charging ? 'Đang sạc' : 'Pin') + ')';
        }
      } catch (e) {}

      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      const webdriverFlag = Boolean(navigator.webdriver);

      let score = 100;
      if (webdriverFlag) score -= 45;
      if (!window.__GHOST_PROFILE_INJECTED__) score -= 25;
      if (webrtcStatus === 'ACTIVE') score -= 10;
      const grade = score >= 95 ? 'A+ (ẨN DANH TUYỆT ĐỐI)' : (score >= 80 ? 'A (AN TOÀN)' : 'C (CẢNH BÁO)');

      const report = {
        scannedAt: new Date().toISOString(),
        profileId: window.__GHOST_PROFILE_CFG__?.profileId || '${profileId || 'unknown'}',
        profileName: window.__GHOST_PROFILE_CFG__?.profileName || '${profileTitle}',
        stealthInjected: Boolean(window.__GHOST_PROFILE_INJECTED__),
        trustScore: score,
        trustGrade: grade,
        webdriver: webdriverFlag,
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory || 8,
        screenResolution: screen.width + 'x' + screen.height + ' (@' + window.devicePixelRatio + 'x)',
        timezone: tz,
        languages: (navigator.languages || [navigator.language]).join(', '),
        canvasHash,
        webglVendor: webgl.vendor,
        webglRenderer: webgl.renderer,
        webglHash: webgl.hash,
        audioHash,
        clientRectsHash,
        webrtcStatus,
        mediaDevicesHash,
        deviceCount,
        batteryInfo,
        latitude: window.__GHOST_PROFILE_CFG__?.latitude ?? null,
        longitude: window.__GHOST_PROFILE_CFG__?.longitude ?? null
      };

      window.__GHOST_FP_REPORT__ = report;

      document.getElementById('trust-score').textContent = score + '/100';
      document.getElementById('trust-grade').textContent = grade;
      document.getElementById('lab-subtitle').textContent =
        'Hồ sơ: ' + report.profileName + ' • Múi giờ: ' + report.timezone + ' • Trạng thái chống phát hiện: ĐÃ KÍCH HOẠT 12 LỚP';

      document.getElementById('out-canvas-hash').textContent = canvasHash;
      document.getElementById('out-rects-hash').textContent = clientRectsHash;
      document.getElementById('out-screen').textContent = report.screenResolution + ' • ' + screen.colorDepth + '-bit';

      document.getElementById('out-webgl-vendor').textContent = webgl.vendor;
      document.getElementById('out-webgl-renderer').textContent = webgl.renderer;
      document.getElementById('out-webgl-hash').textContent = webgl.hash;
      document.getElementById('out-audio-hash').textContent = audioHash;

      document.getElementById('out-webdriver').textContent = webdriverFlag ? '❌ true (BỊ LỘ BOT)' : '✅ false (Người dùng thật)';
      document.getElementById('out-platform').textContent = report.platform;
      document.getElementById('out-hw').textContent = report.hardwareConcurrency + ' Cores / ' + report.deviceMemory + ' GB RAM';
      document.getElementById('out-ua').textContent = report.userAgent;

      document.getElementById('out-tz').textContent = report.timezone;
      document.getElementById('out-lang').textContent = report.languages;
      document.getElementById('out-webrtc').textContent = webrtcStatus;
      document.getElementById('out-devices').textContent = deviceCount + ' thiết bị (' + mediaDevicesHash.slice(0, 8) + ') • Pin ' + batteryInfo;
    }

    window.addEventListener('DOMContentLoaded', runFullScan);
  </script>
</body>
</html>`;
}

// ============================================================================
// CHROME / EDGE CDP ENGINE & RUNNING PROFILE CONTROLLER
// ============================================================================
function findBrowserExecutable() {
  const candidates = [
    process.env.CHROME_PATH,
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'
  ].filter(Boolean);

  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch {}
  }
  return null;
}

function getFreeLocalPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
    srv.on('error', reject);
  });
}

function fetchJsonLocal(url, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout: timeoutMs }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
  });
}

const activeSessions = new Map();

class AntiDetectSession {
  constructor(profile, { headless = true } = {}) {
    this.profile = profile;
    this.headless = Boolean(headless);
    this.proc = null;
    this.ws = null;
    this.debugPort = 0;
    this.msgId = 1;
    this.pending = new Map();
    this.browserName = '';
    this.startedAt = new Date().toISOString();
    this.profileDir = path.join(PROFILES_DIR, profile.id);
  }

  async launch() {
    const browserPath = findBrowserExecutable();
    if (!browserPath) {
      throw new Error('Không tìm thấy Google Chrome hoặc Microsoft Edge trên máy tính.');
    }
    this.browserName = path.basename(browserPath);
    this.debugPort = await getFreeLocalPort();

    const isDirLocked = activeSessions.has(this.profile.id) && this.headless;
    const userDataDir = isDirLocked
      ? path.join(os.tmpdir(), `ghostprofile-verify-${this.profile.id}-${Date.now()}`)
      : this.profileDir;
    this.tempDirUsed = isDirLocked ? userDataDir : null;
    fs.mkdirSync(userDataDir, { recursive: true });

    const fp = this.profile.fingerprint || {};
    const proxy = this.profile.proxy || {};

    const args = [
      ...(this.headless ? ['--headless=new'] : ['--new-window']),
      `--window-size=${Math.min(fp.screenWidth || 1280, 1440)},${Math.min(fp.screenHeight || 860, 920)}`,
      `--user-agent=${fp.userAgent || ''}`,
      `--lang=${fp.locale || 'vi-VN'}`,
      '--disable-blink-features=AutomationControlled',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--enforce-webrtc-ip-permission-check',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-popup-blocking',
      '--ignore-certificate-errors',
      `--remote-debugging-port=${this.debugPort}`,
      `--user-data-dir=${userDataDir}`
    ];

    if (proxy.mode && proxy.mode !== 'direct' && proxy.host && proxy.port) {
      args.push(`--proxy-server=${proxy.mode}://${proxy.host}:${proxy.port}`);
    }

    args.push('about:blank');

    this.proc = spawn(browserPath, args, {
      stdio: 'ignore',
      windowsHide: this.headless
    });

    this.proc.on('exit', () => {
      if (!this.headless && activeSessions.get(this.profile.id) === this) {
        activeSessions.delete(this.profile.id);
      }
    });

    let wsUrl = null;
    for (let i = 0; i < 35; i++) {
      await new Promise((r) => setTimeout(r, 150));
      const targets = await fetchJsonLocal(`http://127.0.0.1:${this.debugPort}/json/list`);
      if (Array.isArray(targets)) {
        const pageTarget = targets.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
        if (pageTarget) {
          wsUrl = pageTarget.webSocketDebuggerUrl;
          break;
        }
      }
    }

    if (!wsUrl) {
      await this.close();
      throw new Error('Không thể kết nối tới cổng điều khiển DevTools của trình duyệt.');
    }

    await new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      this.ws = ws;
      const timer = setTimeout(() => reject(new Error('CDP WebSocket connection timeout')), 5000);

      ws.addEventListener('open', () => {
        clearTimeout(timer);
        resolve();
      });

      ws.addEventListener('message', (ev) => {
        try {
          const data = JSON.parse(typeof ev.data === 'string' ? ev.data : ev.data.toString());
          if (data.id && this.pending.has(data.id)) {
            const { resolve: resFn, reject: rejFn } = this.pending.get(data.id);
            this.pending.delete(data.id);
            if (data.error) rejFn(new Error(data.error.message || 'CDP Error'));
            else resFn(data.result);
          }
        } catch {}
      });

      ws.addEventListener('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });

    await this.applyAntiDetectOverrides();
  }

  async applyAntiDetectOverrides() {
    const fp = this.profile.fingerprint || {};
    const injectionScript = buildStealthInjectionScript(this.profile);

    await this.send('Page.enable');
    await this.send('Runtime.enable');
    await this.send('Network.enable');

    await this.send('Page.addScriptToEvaluateOnNewDocument', {
      source: injectionScript
    });

    await this.send('Network.setUserAgentOverride', {
      userAgent: fp.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      acceptLanguage: Array.isArray(fp.languages) ? fp.languages.join(',') : (fp.locale || 'vi-VN'),
      platform: fp.platform || 'Win32'
    }).catch(() => {});

    if (fp.timezone) {
      await this.send('Emulation.setTimezoneOverride', {
        timezoneId: fp.timezone
      }).catch(() => {});
    }

    if (typeof fp.latitude === 'number' && typeof fp.longitude === 'number') {
      await this.send('Emulation.setGeolocationOverride', {
        latitude: fp.latitude,
        longitude: fp.longitude,
        accuracy: fp.accuracyMeters || 20
      }).catch(() => {});
    }

    if (fp.locale) {
      await this.send('Emulation.setLocaleOverride', {
        locale: fp.locale
      }).catch(() => {});
    }
  }

  send(method, params = {}, timeoutMs = 12000) {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        return reject(new Error('Phiên trình duyệt CDP đã đóng'));
      }
      const id = this.msgId++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP Timeout: ${method}`));
      }, timeoutMs);

      this.pending.set(id, {
        resolve: (res) => {
          clearTimeout(timer);
          resolve(res);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        }
      });

      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  async goto(url, waitMs = 900) {
    await this.send('Page.navigate', { url });
    await new Promise((r) => setTimeout(r, waitMs));
    await this.evaluate(buildStealthInjectionScript(this.profile)).catch(() => {});
  }

  async evaluate(expression) {
    const res = await this.send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise: true
    });
    if (res && res.exceptionDetails) {
      throw new Error(res.exceptionDetails.text || 'JS Evaluation Error');
    }
    return res?.result?.value;
  }

  async captureScreenshot(prefix = 'fp') {
    pruneOldScreenshots(30);
    const res = await this.send('Page.captureScreenshot', { format: 'png' });
    if (!res || !res.data) return null;
    const filename = `${prefix}_${this.profile.id}_${Date.now()}.png`;
    const filePath = path.join(SCREENSHOTS_DIR, filename);
    fs.writeFileSync(filePath, Buffer.from(res.data, 'base64'));
    return `/screenshots/${filename}`;
  }

  async close() {
    try {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        await this.send('Browser.close', {}, 1500).catch(() => {});
        this.ws.close();
      }
    } catch {}
    try {
      if (this.proc && !this.proc.killed) {
        this.proc.kill('SIGTERM');
      }
    } catch {}
    if (this.tempDirUsed) {
      setTimeout(() => {
        try { fs.rmSync(this.tempDirUsed, { recursive: true, force: true }); } catch {}
      }, 600);
    }
    if (!this.headless && activeSessions.get(this.profile.id) === this) {
      activeSessions.delete(this.profile.id);
    }
  }
}

async function verifyProfileFingerprint(profile, serverPort = PORT) {
  const session = new AntiDetectSession(profile, { headless: true });
  try {
    await session.launch();
    const labUrl = `http://127.0.0.1:${serverPort}/lab/fingerprint?profileId=${encodeURIComponent(profile.id)}`;
    await session.goto(labUrl, 750);

    let report = null;
    for (let i = 0; i < 12; i++) {
      report = await session.evaluate('window.__GHOST_FP_REPORT__ || null');
      if (report && report.canvasHash && report.audioHash) break;
      await new Promise((r) => setTimeout(r, 150));
    }

    if (!report) {
      throw new Error('Không đọc được báo cáo vân tay từ phòng Lab.');
    }

    const screenshotUrl = await session.captureScreenshot('fp');
    report.screenshotUrl = screenshotUrl;
    report.browserUsed = session.browserName;

    profile.lastVerifiedReport = report;
    saveStore();
    return report;
  } finally {
    await session.close();
  }
}

// ============================================================================
// HTTP SERVER & REST API
// ============================================================================
function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > 10 * 1024 * 1024) {
        req.destroy();
        return reject(new Error('Payload too large'));
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(text ? JSON.parse(text) : {});
      } catch (err) {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(data));
}

function serializeProfileWithRuntime(p) {
  const running = activeSessions.get(p.id);
  const profileDir = path.join(PROFILES_DIR, p.id);
  const totp = p.totpSecret ? generateTotpCode(p.totpSecret) : null;
  return {
    ...p,
    totpLive: totp,
    runtime: {
      isRunning: Boolean(running),
      pid: running?.proc?.pid || null,
      debugPort: running?.debugPort || null,
      startedAt: running?.startedAt || null,
      hasPersistentStorage: fs.existsSync(profileDir)
    }
  };
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    return sendJson(res, 200, { ok: true });
  }

  const urlObj = new URL(req.url, `http://${req.headers.host || `localhost:${PORT}`}`);
  const pathname = urlObj.pathname;
  const activePort = server.address()?.port || PORT;

  try {
    // 1. Built-in Fingerprint Scanner Laboratory Page
    if (pathname === '/lab/fingerprint' && req.method === 'GET') {
      const profileId = urlObj.searchParams.get('profileId') || '';
      const html = renderFingerprintLabHtml(profileId);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    }

    // 1b. Built-in Warmup & Auto-Fill Login Sandbox Pages (/warmup/:stage)
    const warmupPageMatch = pathname.match(/^\/warmup\/(search|news|marketplace)$/);
    if (warmupPageMatch && req.method === 'GET') {
      const stage = warmupPageMatch[1];
      const profileId = urlObj.searchParams.get('profileId') || 'ghost';
      const cookieVal = `trust_${stage}_${profileId}_${Date.now()}`;
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Set-Cookie': [
          `gp_warmup_${stage}=${cookieVal}; Path=/; Max-Age=2592000`,
          `gp_trust_score=A_PLUS_VERIFIED; Path=/; Max-Age=2592000`
        ]
      });
      return res.end(renderWarmupStageHtml(stage, profileId));
    }

    // 2. Serve Screenshots
    if (pathname.startsWith('/screenshots/') && req.method === 'GET') {
      const safeName = path.basename(pathname);
      const filePath = path.join(SCREENSHOTS_DIR, safeName);
      if (fs.existsSync(filePath)) {
        res.writeHead(200, { 'Content-Type': 'image/png' });
        return fs.createReadStream(filePath).pipe(res);
      }
      return sendJson(res, 404, { ok: false, error: 'Screenshot not found' });
    }

    // 3. GET /api/state — Full Dashboard State
    if (pathname === '/api/state' && req.method === 'GET') {
      const browserExec = findBrowserExecutable();
      return sendJson(res, 200, {
        ok: true,
        browserDetected: browserExec ? path.basename(browserExec) : null,
        browserPath: browserExec,
        profiles: store.profiles.map(serializeProfileWithRuntime),
        comparisons: store.comparisons,
        geoPresets: GEO_PRESETS
      });
    }

    // 3b. GET /api/totp — Compute live 6-digit TOTP code for any Base32 secret
    if (pathname === '/api/totp' && req.method === 'GET') {
      const secret = urlObj.searchParams.get('secret') || '';
      const totp = generateTotpCode(secret);
      if (!totp) return sendJson(res, 400, { ok: false, error: 'Secret Base32 không hợp lệ' });
      return sendJson(res, 200, { ok: true, ...totp });
    }

    // 4. POST /api/fingerprint/generate — Generate Random Coherent Fingerprint
    if (pathname === '/api/fingerprint/generate' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const fp = generateCoherentFingerprint({
        osKey: body.osKey || 'windows',
        regionKey: body.regionKey || 'VN'
      });
      return sendJson(res, 200, { ok: true, fingerprint: fp, totpSecret: randomBase32Secret(16) });
    }

    // 5. POST /api/profiles — Create New Profile
    if (pathname === '/api/profiles' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const id = `prof-${Date.now().toString(36)}-${crypto.randomBytes(2).toString('hex')}`;
      const osKey = body.osKey || body.fingerprint?.osKey || 'windows';
      const regionKey = body.regionKey || body.fingerprint?.regionCode || 'VN';
      const fp = body.fingerprint && body.fingerprint.userAgent
        ? { ...generateCoherentFingerprint({ osKey, regionKey }), ...body.fingerprint }
        : generateCoherentFingerprint({ osKey, regionKey });

      const newProfile = {
        id,
        name: (body.name || `Profile ${store.profiles.length + 1}`).trim(),
        platformTag: (body.platformTag || 'Multi-Account').trim(),
        groupName: (body.groupName || 'Default Group').trim(),
        startUrl: (body.startUrl || `http://localhost:${activePort}/lab/fingerprint?profileId=${id}`).trim(),
        notes: (body.notes || '').trim(),
        accountUsername: (body.accountUsername || '').trim(),
        accountPassword: (body.accountPassword || '').trim(),
        totpSecret: (body.totpSecret || randomBase32Secret(16)).trim(),
        proxy: {
          mode: body.proxy?.mode || 'direct',
          host: (body.proxy?.host || '').trim(),
          port: String(body.proxy?.port || '').trim(),
          username: (body.proxy?.username || '').trim(),
          password: (body.proxy?.password || '').trim(),
          simulatedPublicIp: body.proxy?.simulatedPublicIp || `${crypto.randomInt(14, 210)}.${crypto.randomInt(10, 250)}.${crypto.randomInt(10, 250)}.${crypto.randomInt(2, 250)}`
        },
        fingerprint: fp,
        lastVerifiedReport: null,
        lastWarmupReport: null,
        lastLaunchAt: null,
        createdAt: new Date().toISOString()
      };

      store.profiles.unshift(newProfile);
      saveStore();
      return sendJson(res, 200, { ok: true, profile: serializeProfileWithRuntime(newProfile) });
    }

    // 6. PUT /api/profiles/:id — Update Profile
    const profMatch = pathname.match(/^\/api\/profiles\/([^/]+)$/);
    if (profMatch && req.method === 'PUT') {
      const id = profMatch[1];
      const profile = store.profiles.find((p) => p.id === id);
      if (!profile) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });

      const body = await parseJsonBody(req);
      if (typeof body.name === 'string' && body.name.trim()) profile.name = body.name.trim();
      if (typeof body.platformTag === 'string') profile.platformTag = body.platformTag.trim();
      if (typeof body.groupName === 'string') profile.groupName = body.groupName.trim();
      if (typeof body.startUrl === 'string' && body.startUrl.trim()) profile.startUrl = body.startUrl.trim();
      if (typeof body.notes === 'string') profile.notes = body.notes.trim();
      if (typeof body.accountUsername === 'string') profile.accountUsername = body.accountUsername.trim();
      if (typeof body.accountPassword === 'string') profile.accountPassword = body.accountPassword.trim();
      if (typeof body.totpSecret === 'string') profile.totpSecret = body.totpSecret.trim();
      if (body.proxy && typeof body.proxy === 'object') {
        profile.proxy = { ...profile.proxy, ...body.proxy };
      }
      if (body.fingerprint && typeof body.fingerprint === 'object') {
        profile.fingerprint = { ...profile.fingerprint, ...body.fingerprint };
      }

      saveStore();
      return sendJson(res, 200, { ok: true, profile: serializeProfileWithRuntime(profile) });
    }

    // 7. DELETE /api/profiles/:id — Delete Profile & Persistent Storage
    if (profMatch && req.method === 'DELETE') {
      const id = profMatch[1];
      const idx = store.profiles.findIndex((p) => p.id === id);
      if (idx === -1) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });

      if (activeSessions.has(id)) {
        await activeSessions.get(id).close();
      }
      const profileDir = path.join(PROFILES_DIR, id);
      try {
        if (fs.existsSync(profileDir)) fs.rmSync(profileDir, { recursive: true, force: true });
      } catch {}

      store.profiles.splice(idx, 1);
      saveStore();
      return sendJson(res, 200, { ok: true, deletedId: id });
    }

    // 8. POST /api/profiles/:id/clone — Clone Profile with Fresh Unique Hardware Noise Seeds
    const cloneMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/clone$/);
    if (cloneMatch && req.method === 'POST') {
      const source = store.profiles.find((p) => p.id === cloneMatch[1]);
      if (!source) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile gốc' });

      const newId = `prof-${Date.now().toString(36)}-${crypto.randomBytes(2).toString('hex')}`;
      const cloned = JSON.parse(JSON.stringify(source));
      cloned.id = newId;
      cloned.name = `${source.name} (Bản sao)`;
      cloned.startUrl = `http://localhost:${activePort}/lab/fingerprint?profileId=${newId}`;
      cloned.fingerprint.canvasSeed = randomSeedInt();
      cloned.fingerprint.webglSeed = randomSeedInt();
      cloned.fingerprint.audioSeed = randomSeedInt();
      cloned.fingerprint.clientRectsSeed = randomSeedInt();
      cloned.fingerprint.mediaDevicesSeed = crypto.randomBytes(6).toString('hex');
      cloned.lastVerifiedReport = null;
      cloned.lastWarmupReport = null;
      cloned.createdAt = new Date().toISOString();

      store.profiles.unshift(cloned);
      saveStore();
      return sendJson(res, 200, { ok: true, profile: serializeProfileWithRuntime(cloned) });
    }

    // 9. POST /api/profiles/:id/regenerate-fp — Randomize Hardware Fingerprint for Existing Profile
    const regenMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/regenerate-fp$/);
    if (regenMatch && req.method === 'POST') {
      const profile = store.profiles.find((p) => p.id === regenMatch[1]);
      if (!profile) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });
      const body = await parseJsonBody(req);
      const osKey = body.osKey || profile.fingerprint?.osKey || 'windows';
      const regionKey = body.regionKey || profile.fingerprint?.regionCode || 'VN';

      profile.fingerprint = generateCoherentFingerprint({ osKey, regionKey });
      profile.lastVerifiedReport = null;
      saveStore();
      return sendJson(res, 200, { ok: true, profile: serializeProfileWithRuntime(profile) });
    }

    // 10. POST /api/profiles/bulk-create — Bulk Factory Generator
    if (pathname === '/api/profiles/bulk-create' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const count = Math.max(1, Math.min(30, Number(body.count || 5)));
      const prefix = (body.prefix || 'Account').trim();
      const platformTag = (body.platformTag || 'Multi-Account').trim();
      const groupName = (body.groupName || 'Bulk Batch').trim();
      const osMode = body.osMode || 'mix';
      const regionKey = body.regionKey || 'VN';
      const proxyLines = String(body.proxyListText || '')
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);

      const created = [];
      for (let i = 0; i < count; i++) {
        const osKey = osMode === 'mix' ? (i % 2 === 0 ? 'windows' : 'macos') : osMode;
        const id = `prof-b${Date.now().toString(36)}-${i}-${crypto.randomBytes(2).toString('hex')}`;
        const fp = generateCoherentFingerprint({ osKey, regionKey });

        let proxyObj = {
          mode: 'direct',
          host: '',
          port: '',
          username: '',
          password: '',
          simulatedPublicIp: `${crypto.randomInt(20, 210)}.${crypto.randomInt(10, 250)}.${crypto.randomInt(10, 250)}.${crypto.randomInt(2, 250)}`
        };

        if (proxyLines[i]) {
          const parts = proxyLines[i].replace(/^https?:\/\/|^socks5:\/\//i, '').split(':');
          if (parts.length >= 2) {
            proxyObj = {
              mode: proxyLines[i].startsWith('socks') ? 'socks5' : 'http',
              host: parts[0],
              port: parts[1],
              username: parts[2] || '',
              password: parts[3] || '',
              simulatedPublicIp: parts[0]
            };
          }
        }

        const item = {
          id,
          name: `${prefix} #${String(i + 1).padStart(2, '0')} (${fp.osKey === 'macos' ? 'Mac' : 'Win'} • ${regionKey})`,
          platformTag,
          groupName,
          startUrl: body.startUrl || `http://localhost:${activePort}/lab/fingerprint?profileId=${id}`,
          notes: `Tạo hàng loạt (${count} profiles) • Hạt giống Canvas #${fp.canvasSeed}`,
          accountUsername: `${prefix.toLowerCase().replace(/[^a-z0-9]/g, '_')}_${i + 1}@mmo.io`,
          accountPassword: `Pass@${crypto.randomInt(10000, 99999)}!`,
          totpSecret: randomBase32Secret(16),
          proxy: proxyObj,
          fingerprint: fp,
          lastVerifiedReport: null,
          lastWarmupReport: null,
          lastLaunchAt: null,
          createdAt: new Date().toISOString()
        };

        store.profiles.push(item);
        created.push(serializeProfileWithRuntime(item));
      }

      saveStore();
      return sendJson(res, 200, { ok: true, count: created.length, created });
    }

    // 11. POST /api/profiles/:id/launch — Launch Visible Anti-Detect Browser Window
    const launchMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/launch$/);
    if (launchMatch && req.method === 'POST') {
      const id = launchMatch[1];
      const profile = store.profiles.find((p) => p.id === id);
      if (!profile) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });

      if (activeSessions.has(id)) {
        const existing = activeSessions.get(id);
        return sendJson(res, 200, {
          ok: true,
          alreadyRunning: true,
          profile: serializeProfileWithRuntime(profile),
          pid: existing.proc?.pid
        });
      }

      const body = await parseJsonBody(req).catch(() => ({}));
      const targetUrl = body.url || profile.startUrl || `http://localhost:${activePort}/lab/fingerprint?profileId=${id}`;

      const session = new AntiDetectSession(profile, { headless: false });
      await session.launch();
      activeSessions.set(id, session);
      await session.goto(targetUrl, 600);

      profile.lastLaunchAt = new Date().toISOString();
      saveStore();

      return sendJson(res, 200, {
        ok: true,
        profile: serializeProfileWithRuntime(profile),
        pid: session.proc?.pid,
        debugPort: session.debugPort,
        targetUrl
      });
    }

    // 12. POST /api/profiles/:id/stop — Stop Visible Browser Window
    const stopMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/stop$/);
    if (stopMatch && req.method === 'POST') {
      const id = stopMatch[1];
      const profile = store.profiles.find((p) => p.id === id);
      if (!profile) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });

      if (activeSessions.has(id)) {
        await activeSessions.get(id).close();
      }
      return sendJson(res, 200, {
        ok: true,
        profile: serializeProfileWithRuntime(profile)
      });
    }

    // 13. POST /api/profiles/:id/verify — Run 1-Click Headless Fingerprint Verification
    const verifyMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/verify$/);
    if (verifyMatch && req.method === 'POST') {
      const id = verifyMatch[1];
      const profile = store.profiles.find((p) => p.id === id);
      if (!profile) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });

      const report = await verifyProfileFingerprint(profile, activePort);
      return sendJson(res, 200, {
        ok: true,
        report,
        profile: serializeProfileWithRuntime(profile)
      });
    }

    // 14. POST /api/profiles/compare-matrix — Multi-Profile Fingerprint Uniqueness Matrix
    if (pathname === '/api/profiles/compare-matrix' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      let ids = Array.isArray(body.profileIds) ? body.profileIds : [];
      if (ids.length < 2) {
        ids = store.profiles.slice(0, 3).map((p) => p.id);
      }

      const reports = [];
      for (const id of ids) {
        const prof = store.profiles.find((p) => p.id === id);
        if (!prof) continue;
        const rep = await verifyProfileFingerprint(prof, activePort);
        reports.push(rep);
      }

      const uniqueCanvas = new Set(reports.map((r) => r.canvasHash)).size;
      const uniqueAudio = new Set(reports.map((r) => r.audioHash)).size;
      const uniqueRects = new Set(reports.map((r) => r.clientRectsHash)).size;
      const uniqueDevices = new Set(reports.map((r) => r.mediaDevicesHash)).size;
      const uniqueWebgl = new Set(reports.map((r) => r.webglHash)).size;
      const total = reports.length;

      const collisionDetected =
        uniqueCanvas < total ||
        uniqueAudio < total ||
        uniqueRects < total ||
        uniqueDevices < total;

      const matrixSummary = {
        id: `cmp_${Date.now()}`,
        comparedAt: new Date().toISOString(),
        totalProfiles: total,
        collisionFree: !collisionDetected,
        uniquenessStats: {
          canvasUnique: `${uniqueCanvas}/${total}`,
          audioUnique: `${uniqueAudio}/${total}`,
          clientRectsUnique: `${uniqueRects}/${total}`,
          mediaDevicesUnique: `${uniqueDevices}/${total}`,
          webglUnique: `${uniqueWebgl}/${total}`
        },
        reports
      };

      store.comparisons.unshift(matrixSummary);
      store.comparisons = store.comparisons.slice(0, 20);
      saveStore();

      return sendJson(res, 200, { ok: true, matrix: matrixSummary });
    }

    // 15. POST /api/profiles/:id/cookies — Get / Import / Clear Profile Cookies via CDP
    const cookieMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/cookies$/);
    if (cookieMatch && req.method === 'POST') {
      const id = cookieMatch[1];
      const profile = store.profiles.find((p) => p.id === id);
      if (!profile) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });

      const body = await parseJsonBody(req);
      const action = body.action || 'get';

      const existing = activeSessions.get(id);
      const session = existing || new AntiDetectSession(profile, { headless: true });
      if (!existing) await session.launch();

      try {
        if (action === 'import' && Array.isArray(body.cookies)) {
          const validCookies = body.cookies
            .filter((c) => c && c.name && (c.domain || c.url))
            .map((c) => ({
              name: String(c.name),
              value: String(c.value ?? ''),
              domain: c.domain || new URL(c.url).hostname,
              path: c.path || '/',
              secure: Boolean(c.secure),
              httpOnly: Boolean(c.httpOnly)
            }));
          if (validCookies.length > 0) {
            await session.send('Network.setCookies', { cookies: validCookies });
          }
        } else if (action === 'clear') {
          await session.send('Network.clearBrowserCookies');
        }

        const cookieRes = await session.send('Network.getAllCookies');
        const cookies = cookieRes?.cookies || [];
        return sendJson(res, 200, {
          ok: true,
          action,
          count: cookies.length,
          cookies
        });
      } finally {
        if (!existing) await session.close();
      }
    }

    // 16. POST /api/profiles/:id/sync-netpulse — Sync Profile Cookies & Fingerprint to NetPulse (4080)
    const syncMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/sync-netpulse$/);
    if (syncMatch && req.method === 'POST') {
      const id = syncMatch[1];
      const profile = store.profiles.find((p) => p.id === id);
      if (!profile) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });

      const body = await parseJsonBody(req).catch(() => ({}));
      const netpulseUrl = (body.netpulseUrl || 'http://localhost:4080').replace(/\/+$/, '');

      const existing = activeSessions.get(id);
      const session = existing || new AntiDetectSession(profile, { headless: true });
      if (!existing) await session.launch();

      let cookies = [];
      try {
        const cRes = await session.send('Network.getAllCookies');
        cookies = cRes?.cookies || [];
      } finally {
        if (!existing) await session.close();
      }

      const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
      let netpulseSynced = false;
      try {
        const resNp = await fetch(`${netpulseUrl}/api/env`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            envVars: {
              GHOST_PROFILE_ID: profile.id,
              GHOST_PROFILE_NAME: profile.name,
              USER_AGENT: profile.fingerprint.userAgent,
              COOKIE_HEADER: cookieHeader || `ghost_profile=${profile.id}`
            }
          })
        });
        netpulseSynced = resNp.ok;
      } catch {}

      return sendJson(res, 200, {
        ok: true,
        profileId: profile.id,
        cookieCount: cookies.length,
        userAgent: profile.fingerprint.userAgent,
        netpulseSynced
      });
    }

    // 17. POST /api/profiles/:id/warmup — Cookie Robot & Account Warmer + Auto-Fill 2FA Demo
    const warmupMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/warmup$/);
    if (warmupMatch && req.method === 'POST') {
      const id = warmupMatch[1];
      const profile = store.profiles.find((p) => p.id === id);
      if (!profile) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });

      const body = await parseJsonBody(req).catch(() => ({}));
      const defaultSites = [
        `http://127.0.0.1:${activePort}/warmup/search?profileId=${encodeURIComponent(id)}`,
        `http://127.0.0.1:${activePort}/warmup/news?profileId=${encodeURIComponent(id)}`,
        `http://127.0.0.1:${activePort}/warmup/marketplace?profileId=${encodeURIComponent(id)}`
      ];
      const urls = Array.isArray(body.urls) && body.urls.length > 0 ? body.urls : defaultSites;

      const t0 = Date.now();
      const existing = activeSessions.get(id);
      const session = existing || new AntiDetectSession(profile, { headless: true });
      if (!existing) await session.launch();

      try {
        const beforeCookies = (await session.send('Network.getAllCookies'))?.cookies || [];
        const visitedLog = [];

        for (const u of urls) {
          await session.goto(u, 350);
          // Human-like scroll & interaction
          await session.evaluate(`
            (function() {
              window.scrollBy({ top: 260, behavior: 'smooth' });
              document.cookie = 'gp_human_scroll_' + Date.now() + '=1; path=/; max-age=86400';
              return document.title;
            })()
          `).catch(() => '');

          const title = await session.evaluate('document.title').catch(() => u);
          visitedLog.push({ url: u, title, visitedAt: new Date().toISOString() });
        }

        // Also perform 1-click Auto-Fill on the marketplace login page if present
        const totpObj = profile.totpSecret ? generateTotpCode(profile.totpSecret) : { code: '123456' };
        const autoFilled = await session.evaluate(`
          (function() {
            const uEl = document.querySelector('#login-username, input[name="username"], input[type="email"]');
            const pEl = document.querySelector('#login-password, input[name="password"], input[type="password"]');
            const tEl = document.querySelector('#login-totp, input[name="totp"], input[name="otp"]');
            const btn = document.querySelector('#btn-login-submit');
            if (!uEl) return false;
            uEl.value = ${JSON.stringify(profile.accountUsername || 'user@ghostprofile.io')};
            if (pEl) pEl.value = ${JSON.stringify(profile.accountPassword || 'SecretPass#2026')};
            if (tEl) tEl.value = ${JSON.stringify(totpObj?.code || '888999')};
            if (btn) btn.click();
            return true;
          })()
        `).catch(() => false);

        const afterCookies = (await session.send('Network.getAllCookies'))?.cookies || [];
        const screenshotUrl = await session.captureScreenshot('warmup');

        const warmupReport = {
          completedAt: new Date().toISOString(),
          durationMs: Date.now() - t0,
          sitesVisited: visitedLog.length,
          visitedLog,
          cookiesBefore: beforeCookies.length,
          cookiesAfter: afterCookies.length,
          autoFilled2FA: Boolean(autoFilled),
          totpUsed: totpObj?.code || null,
          screenshotUrl
        };

        profile.lastWarmupReport = warmupReport;
        saveStore();

        return sendJson(res, 200, {
          ok: true,
          warmupReport,
          profile: serializeProfileWithRuntime(profile)
        });
      } finally {
        if (!existing) await session.close();
      }
    }

    // 18. POST /api/profiles/:id/autofill — 1-Click Auto-Fill Username + Password + Live 2FA into Running Browser
    const autofillMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/autofill$/);
    if (autofillMatch && req.method === 'POST') {
      const id = autofillMatch[1];
      const profile = store.profiles.find((p) => p.id === id);
      if (!profile) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });

      const totpObj = profile.totpSecret ? generateTotpCode(profile.totpSecret) : { code: '000000' };
      const existing = activeSessions.get(id);
      const session = existing || new AntiDetectSession(profile, { headless: true });
      if (!existing) {
        await session.launch();
        await session.goto(`http://127.0.0.1:${activePort}/warmup/marketplace?profileId=${encodeURIComponent(id)}`, 400);
      }

      try {
        const result = await session.evaluate(`
          (function() {
            const uEl = document.querySelector('#login-username, input[name="username"], input[name="email"], input[type="email"], input[type="text"]');
            const pEl = document.querySelector('#login-password, input[name="password"], input[type="password"]');
            const tEl = document.querySelector('#login-totp, input[name="totp"], input[name="otp"], input[name="code"]');
            const btn = document.querySelector('#btn-login-submit');
            let filled = 0;
            if (uEl) { uEl.value = ${JSON.stringify(profile.accountUsername || '')}; filled++; }
            if (pEl) { pEl.value = ${JSON.stringify(profile.accountPassword || '')}; filled++; }
            if (tEl) { tEl.value = ${JSON.stringify(totpObj?.code || '')}; filled++; }
            if (btn) btn.click();
            return { filledFields: filled, pageTitle: document.title };
          })()
        `);

        return sendJson(res, 200, {
          ok: true,
          totpCode: totpObj?.code || '',
          filledFields: result?.filledFields || 0,
          pageTitle: result?.pageTitle || ''
        });
      } finally {
        if (!existing) await session.close();
      }
    }

    // 19. POST /api/profiles/:id/check-proxy — Live Proxy Connectivity & Auto-Geo Alignment
    const checkProxyMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/check-proxy$/);
    if (checkProxyMatch && req.method === 'POST') {
      const id = checkProxyMatch[1];
      const profile = store.profiles.find((p) => p.id === id);
      if (!profile) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy Profile' });

      const body = await parseJsonBody(req).catch(() => ({}));
      const proxy = profile.proxy || {};
      const regionKey = body.regionKey || profile.fingerprint?.regionCode || 'VN';
      const geo = GEO_PRESETS[regionKey] || GEO_PRESETS.VN;
      const city = pickRandom(geo.cities);

      let latencyMs = crypto.randomInt(18, 64);
      let reachable = true;

      if (proxy.mode && proxy.mode !== 'direct' && proxy.host && proxy.port) {
        const t0 = Date.now();
        reachable = await new Promise((resolve) => {
          const sock = net.createConnection({ host: proxy.host, port: Number(proxy.port), timeout: 2500 }, () => {
            sock.destroy();
            resolve(true);
          });
          sock.on('error', () => resolve(false));
          sock.on('timeout', () => { sock.destroy(); resolve(false); });
        });
        latencyMs = Date.now() - t0;
      }

      // Auto-align timezone, locale, languages, and GPS coordinates with region
      if (body.autoAlignGeo !== false) {
        profile.fingerprint.regionCode = geo.countryCode;
        profile.fingerprint.cityName = city.name;
        profile.fingerprint.timezone = geo.timezone;
        profile.fingerprint.locale = geo.locale;
        profile.fingerprint.languages = [...geo.languages];
        profile.fingerprint.latitude = Number((city.lat + (Math.random() - 0.5) * 0.01).toFixed(5));
        profile.fingerprint.longitude = Number((city.lng + (Math.random() - 0.5) * 0.01).toFixed(5));
        saveStore();
      }

      return sendJson(res, 200, {
        ok: true,
        reachable,
        latencyMs,
        exitIp: proxy.host || proxy.simulatedPublicIp || '113.190.232.88',
        alignedGeo: {
          countryCode: geo.countryCode,
          cityName: city.name,
          timezone: geo.timezone,
          locale: geo.locale
        },
        profile: serializeProfileWithRuntime(profile)
      });
    }

    // 20. GET /api/backup & POST /api/restore
    if (pathname === '/api/backup' && req.method === 'GET') {
      return sendJson(res, 200, {
        ok: true,
        exportedAt: new Date().toISOString(),
        store
      });
    }

    if (pathname === '/api/restore' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const incoming = body.store || body;
      if (!incoming || !Array.isArray(incoming.profiles)) {
        return sendJson(res, 400, { ok: false, error: 'File backup không hợp lệ' });
      }
      store.profiles = incoming.profiles;
      saveStore();
      return sendJson(res, 200, { ok: true, count: store.profiles.length });
    }

    // 21. Static Files from public/
    const safeRel = path.normalize(pathname === '/' ? '/index.html' : pathname).replace(/^(\.\.[/\\])+/, '');
    const filePath = path.join(PUBLIC_DIR, safeRel);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const mimeMap = {
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.json': 'application/json; charset=utf-8',
        '.png': 'image/png',
        '.svg': 'image/svg+xml'
      };
      res.writeHead(200, { 'Content-Type': mimeMap[ext] || 'application/octet-stream' });
      return fs.createReadStream(filePath).pipe(res);
    }

    return sendJson(res, 404, { ok: false, error: 'Not Found' });
  } catch (err) {
    console.error('[GhostProfile API Error]:', err);
    return sendJson(res, 500, { ok: false, error: err.message });
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log('====================================================================');
    console.log(`🎭 GhostProfile PRO MAX — Anti-Detect Browser Manager đang chạy tại:`);
    console.log(`👉 Dashboard:        http://localhost:${PORT}`);
    console.log(`👉 Fingerprint Lab:  http://localhost:${PORT}/lab/fingerprint`);
    console.log('====================================================================');
  });
}

module.exports = { server, generateCoherentFingerprint, buildStealthInjectionScript, generateTotpCode };
