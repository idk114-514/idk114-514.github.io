// ================== 全局变量 ==================
let currentEngine = 'v3'; // 'v1' 或 'v3'

// ================== MoeCipher V1（原版） ==================
const V1 = {
  S: ['哦', '啊', '嗯', '咿', '咕', '哼', '呼', '唔', '齁', '喔'],
  P: ['～', '❤', '…', '！'],
  D: { '哦':0, '啊':1, '嗯':2, '咿':3, '咕':4, '哼':5, '呼':6, '唔':7, '齁':8, '喔':9 },
  Q: { '～':0, '❤':1, '…':2, '！':3 },
  KEY: 'r18_onomatopoeia'
};

async function* v1_sha256Generator(key) {
  const encoder = new TextEncoder();
  let data = encoder.encode(key);
  let hashBuffer = await crypto.subtle.digest('SHA-256', data);
  let hashArray = Array.from(new Uint8Array(hashBuffer));

  while (true) {
    for (let b of hashArray) yield b;
    let hashData = new Uint8Array(hashArray);
    hashBuffer = await crypto.subtle.digest('SHA-256', hashData);
    hashArray = Array.from(new Uint8Array(hashBuffer));
  }
}

async function v1_encrypt(text, key = V1.KEY) {
  const gen = v1_sha256Generator(key);
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);
  const result = [];

  for (const b of bytes) {
    const next = await gen.next();
    const e = b ^ next.value;
    const v = e >> 2;
    result.push(V1.S[Math.floor(v / 10)] + V1.S[v % 10] + V1.P[e & 3]);
  }

  return result.join('');
}

async function v1_decrypt(ciphertext, key = V1.KEY) {
  if (ciphertext.length % 3 !== 0) throw new Error('长度必须为3倍数');

  const gen = v1_sha256Generator(key);
  const result = [];

  for (let i = 0; i < ciphertext.length; i += 3) {
    const a = ciphertext[i], b = ciphertext[i+1], p = ciphertext[i+2];
    if (!(a in V1.D) || !(b in V1.D) || !(p in V1.Q)) throw new Error('无效字符');
    const v = (V1.D[a] * 10 + V1.D[b]) << 2 | V1.Q[p];
    const next = await gen.next();
    result.push(v ^ next.value);
  }

  try {
    return new TextDecoder().decode(new Uint8Array(result));
  } catch {
    throw new Error('密钥错误或密文损坏');
  }
}

// ================== MoeCipher V3（新版） ==================
const V3 = {
  S: ['哦', '啊', '嗯', '咿', '咕', '哼', '呼', '唔', '齁', '喔'],
  P: ['～', '❤', '…', '！'],
  D: { '哦':0, '啊':1, '嗯':2, '咿':3, '咕':4, '哼':5, '呼':6, '唔':7, '齁':8, '喔':9 },
  Q: { '～':0, '❤':1, '…':2, '！':3 },
  KEY: 'r18_onomatopoeia_v3',
  THRESHOLD: 50
};

async function* v3_sha256Generator(key) {
  const encoder = new TextEncoder();
  let data = encoder.encode(key);
  let hashBuffer = await crypto.subtle.digest('SHA-256', data);
  let hashArray = Array.from(new Uint8Array(hashBuffer));

  while (true) {
    for (let b of hashArray) yield b;
    let hashData = new Uint8Array(hashArray);
    hashBuffer = await crypto.subtle.digest('SHA-256', hashData);
    hashArray = Array.from(new Uint8Array(hashBuffer));
  }
}

function v3_encodeByte(byte) {
  const soundVal = byte >> 2;
  const puncIdx = byte & 0b11;
  const s1 = V3.S[Math.floor(soundVal / 10)];
  const s2 = V3.S[soundVal % 10];
  const p = V3.P[puncIdx];
  return s1 + s2 + p;
}

function v3_decodeMoan(moan) {
  if (moan.length !== 3) throw new Error('短句长度必须为3');
  const [a, b, p] = moan;
  if (!(a in V3.D) || !(b in V3.D) || !(p in V3.Q)) throw new Error('无效字符');
  const soundVal = V3.D[a] * 10 + V3.D[b];
  return (soundVal << 2) | V3.Q[p];
}

async function v3_encrypt(text, key = V3.KEY) {
  const encoder = new TextEncoder();
  let bytes = encoder.encode(text);
  let isCompressed = false;

  if (bytes.length > V3.THRESHOLD) {
    try {
      const compressed = pako.deflate(bytes, { level: 9 });
      if (compressed.length < bytes.length) {
        bytes = compressed;
        isCompressed = true;
      }
    } catch (e) {}
  }

  const gen = v3_sha256Generator(key);
  const frames = [];

  // 压缩标记
  const tagByte = isCompressed ? 1 : 0;
  const encTag = tagByte ^ (await gen.next()).value;
  frames.push(v3_encodeByte(encTag));

  for (const byte of bytes) {
    const encByte = byte ^ (await gen.next()).value;
    frames.push(v3_encodeByte(encByte));
  }

  return frames.join('');
}

async function v3_decrypt(ciphertext, key = V3.KEY) {
  if (ciphertext.length % 3 !== 0) throw new Error('密文长度必须为3的倍数');

  const gen = v3_sha256Generator(key);
  const bytes = [];

  // 解密压缩标记
  const tagFrame = ciphertext.slice(0, 3);
  const decTag = v3_decodeMoan(tagFrame) ^ (await gen.next()).value;
  const isCompressed = (decTag & 1) === 1;

  for (let i = 3; i < ciphertext.length; i += 3) {
    const frame = ciphertext.slice(i, i + 3);
    const encByte = v3_decodeMoan(frame);
    const decByte = encByte ^ (await gen.next()).value;
    bytes.push(decByte);
  }

  try {
    const data = new Uint8Array(bytes);
    const finalBytes = isCompressed ? pako.inflate(data) : data;
    return new TextDecoder('utf-8').decode(finalBytes);
  } catch (e) {
    throw new Error('解密失败：密钥错误、密文已损坏或压缩数据无效');
  }
}

// ================== UI 控制 ==================
async function encryptText() {
  const input = document.getElementById('inputText').value.trim();
  const key = document.getElementById('keyInput').value || (currentEngine === 'v1' ? V1.KEY : V3.KEY);
  if (!input) return showToast('请输入内容！', 'info');

  try {
    const result = currentEngine === 'v1'
      ? await v1_encrypt(input, key)
      : await v3_encrypt(input, key);
    document.getElementById('outputText').value = result;
    updateCharCount(result);
  } catch (e) {
    showToast('加密失败: ' + e.message, 'error');
  }
}

async function decryptText() {
  const input = document.getElementById('inputText').value.trim();
  const key = document.getElementById('keyInput').value || (currentEngine === 'v1' ? V1.KEY : V3.KEY);
  if (!input) return showToast('请输入内容！', 'info');

  try {
    const result = currentEngine === 'v1'
      ? await v1_decrypt(input, key)
      : await v3_decrypt(input, key);
    document.getElementById('outputText').value = result;
    updateCharCount(result);
  } catch (e) {
    showToast('解密失败: ' + e.message, 'error');
  }
}

function swapIO() {
  const out = document.getElementById('outputText').value.trim();
  if (!out) return showToast('输出为空', 'error');
  document.getElementById('inputText').value = out;
  document.getElementById('outputText').value = '';
  updateCharCount('');
  showToast('✅ 输出已填入输入框', 'success');
}

function copyResult() {
  const out = document.getElementById('outputText');
  if (!out.value) return showToast('没有内容可复制', 'error');
  out.select();
  document.execCommand('copy');
  showToast('✅ 已复制到剪贴板', 'success');
}

// 实时加密
let debounceTimer;
function debounce(func, delay = 125) {
  return () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(func, delay);
  };
}

async function handleInput() {
  if (!document.getElementById('autoEncryptToggle').checked) return;
  await encryptText();
}

document.getElementById('inputText').addEventListener('input', debounce(handleInput));
document.getElementById('autoEncryptToggle').addEventListener('change', () => {
  if (document.getElementById('autoEncryptToggle').checked) {
    showToast('✅ 实时模式已开启', 'info');
    handleInput();
  } else {
    showToast('⏸️ 实时模式已关闭', 'info');
  }
});

// ============= 引擎切换 =============
function switchEngine() {
  const btn = document.getElementById('engineToggle');
  if (currentEngine === 'v1') {
    currentEngine = 'v3';
    btn.textContent = '🔄 使用 V3 引擎（推荐）';
    btn.style.background = '#4caf50';
  } else {
    currentEngine = 'v1';
    btn.textContent = '🔄 使用 V1 引擎';
    btn.style.background = '#e76f8e';
  }
  showToast(`已切换到 ${currentEngine.toUpperCase()} 引擎`, 'info');
}

// ============= 字符统计 =============
function updateCharCount(text) {
  const count = text ? text.length : 0;
  document.getElementById('charCount').textContent = `字符数: ${count}`;
}

// ============= 自定义 Toast 提示 =============
function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.className = 'toast ' + type;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2000);
}

// 初始化
updateCharCount('');