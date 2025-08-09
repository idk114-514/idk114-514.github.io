//===== MoeCipher 姬言 =====//
// ================== 全局变量 ==================
let currentEngine = 'v3'; // 'v1', 'v3' 或 'v4'
let v4KeyPair = null; // 用于存储V4公私钥对

// ================== MoeCipher V1（原版） ==================
const V1 = {
  S: ['哦', '啊', '嗯', '咿', '咕', '哼', '呼', '唔', '齁', '喔'],
  P: ['～', '❤', '…', '！'],
  D: { '哦':0, '啊':1, '嗯':2, '咿':3, '咕':4, '哼':5, '呼':6, '唔':7, '齁':8, '喔':9 },
  Q: { '～':0, '❤':1, '…':2, '！':3 },
  KEY: 'onanii'
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
  KEY: 'onanii',
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

// ================== MoeCipher V4（新版） ==================
const V4 = {
  SOUND_CHARS: ['哦', '啊', '嗯', '咿', '咕', '哼', '呼', '唔', '齁', '喔'],
  PUNCTUATION_CHARS: ['～', '❤', '…', '！'],
  SOUND_DECODE_MAP: { '哦':0, '啊':1, '嗯':2, '咿':3, '咕':4, '哼':5, '呼':6, '唔':7, '齁':8, '喔':9 },
  KEY: 'onanii',
  CHECKSUM_LENGTH: 4,
  ALGORITHM: {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: "SHA-256"
  },
  SESSION_KEY_ALGO: {
    name: "AES-GCM",
    length: 256
  },
};

async function v4_sha256(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

async function* v4_keystream_generator(key) {
  const encoder = new TextEncoder();
  let seed = await v4_sha256(encoder.encode(key));
  let current_hash = seed;
  while (true) {
    for (const byte of current_hash) {
      yield byte;
    }
    current_hash = await v4_sha256(current_hash);
  }
}

async function v4_encrypt_data(data, keystream_key) {
  const keystream = v4_keystream_generator(keystream_key);
  const encryptedBytes = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    encryptedBytes[i] = data[i] ^ (await keystream.next()).value;
  }
  return encryptedBytes;
}

async function v4_decrypt_data(encryptedData, keystream_key) {
  const keystream = v4_keystream_generator(keystream_key);
  const decryptedBytes = new Uint8Array(encryptedData.length);
  for (let i = 0; i < encryptedData.length; i++) {
    decryptedBytes[i] = encryptedData[i] ^ (await keystream.next()).value;
  }
  return decryptedBytes;
}

// 修正后的函数，处理并保留开头的零字节
function v4_bytesToBase10(bytes) {
  if (bytes.length === 0) return V4.SOUND_CHARS[0];

  let zeroPrefix = '';
  let nonZeroStartIndex = 0;
  while (nonZeroStartIndex < bytes.length && bytes[nonZeroStartIndex] === 0) {
    zeroPrefix += V4.SOUND_CHARS[0];
    nonZeroStartIndex++;
  }

  const nonZeroBytes = bytes.slice(nonZeroStartIndex);
  if (nonZeroBytes.length === 0) return zeroPrefix;

  let bigInt = BigInt(0);
  for (const byte of nonZeroBytes) {
    bigInt = (bigInt << BigInt(8)) + BigInt(byte);
  }
  
  let base10Representation = '';
  let tempInt = bigInt;
  while (tempInt > BigInt(0)) {
    base10Representation = V4.SOUND_CHARS[Number(tempInt % BigInt(10))] + base10Representation;
    tempInt /= BigInt(10);
  }
  return zeroPrefix + base10Representation;
}

// 修正后的函数，处理并还原开头的零字节
function v4_base10ToBytes(base10String) {
  if (!base10String) return new Uint8Array(0);
  
  let zeroPrefixLength = 0;
  while (zeroPrefixLength < base10String.length && base10String[zeroPrefixLength] === V4.SOUND_CHARS[0]) {
    zeroPrefixLength++;
  }

  const nonZeroString = base10String.slice(zeroPrefixLength);

  if (nonZeroString.length === 0) {
      const bytes = new Uint8Array(zeroPrefixLength);
      bytes.fill(0);
      return bytes;
  }

  let bigInt = BigInt(0);
  for (const char of nonZeroString) {
    bigInt = bigInt * BigInt(10) + BigInt(V4.SOUND_DECODE_MAP[char]);
  }
  
  const bytes = [];
  while (bigInt > BigInt(0)) {
    bytes.push(Number(bigInt & BigInt(0xFF)));
    bigInt >>= BigInt(8);
  }
  
  const result = new Uint8Array(zeroPrefixLength + bytes.length);
  result.set(bytes.reverse(), zeroPrefixLength);
  return result;
}

function v4_add_rhythm(base10Representation, key) {
  const rng = new Math.seedrandom(key); // 使用seedrandom确保节奏一致
  const moanString = [];
  let sourceChars = base10Representation.split('');

  while (sourceChars.length > 0) {
    const phraseLen = Math.floor(rng() * 5) + 1; // 1-5
    let phrase = '';
    for (let i = 0; i < phraseLen && sourceChars.length > 0; i++) {
      phrase += sourceChars.shift();
    }
    if (phrase) {
      const punctuation = V4.PUNCTUATION_CHARS[Math.floor(rng() * V4.PUNCTUATION_CHARS.length)];
      moanString.push(phrase + punctuation);
    }
  }
  return moanString.join('');
}

function v4_remove_rhythm(ciphertext) {
  return ciphertext.split('').filter(char => char in V4.SOUND_DECODE_MAP).join('');
}


// --- 新的V4端到端加密核心函数 ---
async function v4_encrypt_e2e(text, publicKey) {
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(text);
  const checksum = (await v4_sha256(plaintextBytes)).slice(0, V4.CHECKSUM_LENGTH);
  const dataWithChecksum = new Uint8Array(checksum.length + plaintextBytes.length);
  dataWithChecksum.set(checksum);
  dataWithChecksum.set(plaintextBytes, checksum.length);

  const compressedData = pako.deflate(dataWithChecksum, { level: 9 });

  // 生成一个临时的会话密钥
  const sessionKey = await crypto.subtle.generateKey(V4.SESSION_KEY_ALGO, true, ["encrypt", "decrypt"]);
  const exportedSessionKey = await crypto.subtle.exportKey("raw", sessionKey);

  // 用公钥加密会话密钥
  const encryptedSessionKey = await crypto.subtle.encrypt(V4.ALGORITHM, publicKey, exportedSessionKey);

  // 用会话密钥加密数据
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt({ name: V4.SESSION_KEY_ALGO.name, iv: iv }, sessionKey, compressedData);

  // 组合密文
  const combinedData = new Uint8Array(4 + encryptedSessionKey.byteLength + iv.byteLength + encryptedData.byteLength);
  let offset = 0;
  
  new DataView(combinedData.buffer).setUint32(offset, encryptedSessionKey.byteLength, false);
  offset += 4;
  
  combinedData.set(new Uint8Array(encryptedSessionKey), offset);
  offset += encryptedSessionKey.byteLength;
  
  combinedData.set(iv, offset);
  offset += iv.byteLength;
  
  combinedData.set(new Uint8Array(encryptedData), offset);

  // 转换为大数和MoeCipher格式
  const base10Representation = v4_bytesToBase10(combinedData);
  return v4_add_rhythm(base10Representation, 'e2e' + JSON.stringify(exportedSessionKey));
}

async function v4_decrypt_e2e(ciphertext, privateKey) {
  const base10Representation = v4_remove_rhythm(ciphertext);
  const combinedData = v4_base10ToBytes(base10Representation);

  if (combinedData.length < 4 + 12) {
    throw new Error("密文无效：数据过短");
  }

  let offset = 0;
  const encryptedSessionKeyLength = new DataView(combinedData.buffer).getUint32(offset, false);
  offset += 4;
  
  if (combinedData.length < offset + encryptedSessionKeyLength + 12) {
      throw new Error("密文无效：数据不完整");
  }

  const encryptedSessionKey = combinedData.slice(offset, offset + encryptedSessionKeyLength);
  offset += encryptedSessionKeyLength;
  const iv = combinedData.slice(offset, offset + 12);
  offset += 12;
  const encryptedData = combinedData.slice(offset);

  // 用私钥解密会话密钥
  const exportedSessionKey = await crypto.subtle.decrypt(V4.ALGORITHM, privateKey, encryptedSessionKey);
  const sessionKey = await crypto.subtle.importKey("raw", exportedSessionKey, V4.SESSION_KEY_ALGO, true, ["encrypt", "decrypt"]);

  // 用会话密钥解密数据
  const compressedData = await crypto.subtle.decrypt({ name: V4.SESSION_KEY_ALGO.name, iv: iv }, sessionKey, encryptedData);

  const decompressedData = pako.inflate(new Uint8Array(compressedData));

  if (decompressedData.length < V4.CHECKSUM_LENGTH) {
    throw new Error("解密失败：密文数据不完整，缺少校验码。");
  }

  const receivedChecksum = decompressedData.slice(0, V4.CHECKSUM_LENGTH);
  const plaintextBytes = decompressedData.slice(V4.CHECKSUM_LENGTH);
  const expectedChecksum = (await v4_sha256(plaintextBytes)).slice(0, V4.CHECKSUM_LENGTH);

  if (receivedChecksum.join(',') !== expectedChecksum.join(',')) {
    throw new Error("校验失败：私钥错误或密文数据已被篡改。");
  }

  return new TextDecoder('utf-8').decode(plaintextBytes);
}


// --- 新的V4简单加密核心函数（与旧版兼容，无E2E） ---
async function v4_encrypt_legacy(text, key = V4.KEY) {
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(text);
  const checksum = (await v4_sha256(plaintextBytes)).slice(0, V4.CHECKSUM_LENGTH);
  const dataWithChecksum = new Uint8Array(checksum.length + plaintextBytes.length);
  dataWithChecksum.set(checksum);
  dataWithChecksum.set(plaintextBytes, checksum.length);
  const compressedData = pako.deflate(dataWithChecksum, { level: 9 });
  const encryptedBytes = await v4_encrypt_data(compressedData, key);
  if (encryptedBytes.length === 0) return "";
  const base10Representation = v4_bytesToBase10(encryptedBytes);
  return v4_add_rhythm(base10Representation, key);
}

async function v4_decrypt_legacy(ciphertext, key = V4.KEY) {
  if (!ciphertext) return "";
  const base10Representation = v4_remove_rhythm(ciphertext);
  if (!base10Representation) throw new Error("密文无效：不包含任何有效的声音字符。");
  const encryptedBytes = v4_base10ToBytes(base10Representation);
  const compressedData = await v4_decrypt_data(encryptedBytes, key);
  
  let decompressedData;
  try {
    decompressedData = pako.inflate(compressedData);
  } catch (e) {
    throw new Error("解密失败：密钥错误或密文已损坏。");
  }

  if (decompressedData.length < V4.CHECKSUM_LENGTH) {
    throw new Error("解密失败：密文数据不完整，缺少校验码。");
  }
  const receivedChecksum = decompressedData.slice(0, V4.CHECKSUM_LENGTH);
  const plaintextBytes = decompressedData.slice(V4.CHECKSUM_LENGTH);
  const expectedChecksum = (await v4_sha256(plaintextBytes)).slice(0, V4.CHECKSUM_LENGTH);

  if (receivedChecksum.join(',') !== expectedChecksum.join(',')) {
    throw new Error("校验失败：密钥错误或密文数据已被篡改。");
  }
  
  try {
    return new TextDecoder('utf-8').decode(plaintextBytes);
  } catch (e) {
    throw new Error("解密失败：最终数据无法被正确解码为UTF-8文本。");
  }
}

// ================== UI 控制 ==================
async function encryptText() {
  const input = document.getElementById('inputText').value.trim();
  if (!input) return showToast('请输入内容！', 'info');

  try {
    let result;
    if (currentEngine === 'v1') {
      const key = document.getElementById('keyInput').value || V1.KEY;
      result = await v1_encrypt(input, key);
    } else if (currentEngine === 'v3') {
      const key = document.getElementById('keyInput').value || V3.KEY;
      result = await v3_encrypt(input, key);
    } else { // 'v4'
      const publicKeyText = document.getElementById('v4PublicKeyInput').value.trim();
      const legacyMode = document.getElementById('v4LegacyToggle').checked;
      if (!legacyMode && !publicKeyText) {
          return showToast('E2E模式需要输入公钥！', 'error');
      }

      if (legacyMode) {
          const key = document.getElementById('keyInput').value || V4.KEY;
          result = await v4_encrypt_legacy(input, key);
      } else {
          // E2E 模式
          const keyBuffer = base64ToArrayBuffer(publicKeyText);
          const publicKey = await crypto.subtle.importKey("spki", keyBuffer, V4.ALGORITHM, true, ["encrypt"]);
          result = await v4_encrypt_e2e(input, publicKey);
      }
    }
    document.getElementById('outputText').value = result;
    updateCharCount(result);
    // 修改：只有当“实时模式”未开启时才显示Toast提示
    if (!document.getElementById('autoEncryptToggle').checked) {
        showToast('加密成功！', 'success');
    }
  } catch (e) {
    showToast('加密失败: ' + e.message, 'error');
    console.error(e);
  }
}

async function decryptText() {
  const input = document.getElementById('inputText').value.trim();
  if (!input) return showToast('请输入内容！', 'info');

  try {
    let result;
    if (currentEngine === 'v1') {
      const key = document.getElementById('keyInput').value || V1.KEY;
      result = await v1_decrypt(input, key);
    } else if (currentEngine === 'v3') {
      const key = document.getElementById('keyInput').value || V3.KEY;
      result = await v3_decrypt(input, key);
    } else { // 'v4'
      const legacyMode = document.getElementById('v4LegacyToggle').checked;
      if (legacyMode) {
        const key = document.getElementById('keyInput').value || V4.KEY;
        result = await v4_decrypt_legacy(input, key);
      } else {
        if (!v4KeyPair || !v4KeyPair.privateKey) {
            return showToast('E2E模式需要先生成或上传密钥对！', 'error');
        }
        result = await v4_decrypt_e2e(input, v4KeyPair.privateKey);
      }
    }
    document.getElementById('outputText').value = result;
    updateCharCount(result);
    showToast('解密成功！', 'success');
  } catch (e) {
    showToast('解密失败: ' + e.message, 'error');
    console.error(e);
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

// ============= 引擎切换 ==================
function switchEngine() {
  const btn = document.getElementById('engineToggle');
  const v4Section = document.getElementById('v4-section');
  const keySection = document.getElementById('key-section');
  
  if (currentEngine === 'v1') {
    currentEngine = 'v3';
    btn.textContent = '♿ 使用 V3 引擎（文本压缩）';
    btn.style.background = '#4caf50';
    document.getElementById('keyInput').value = 'onanii';
    v4Section.style.display = 'none';
    keySection.style.display = 'block';
  } else if (currentEngine === 'v3') {
    currentEngine = 'v4';
    btn.textContent = '🔒 使用 V4 引擎（E2EE测试版）';
    btn.style.background = '#e76f8e';
    document.getElementById('keyInput').value = 'onanii';
    v4Section.style.display = 'block';
    updateV4UI();
  } else { // 'v4'
    currentEngine = 'v1';
    btn.textContent = '🔄 使用 V1 引擎';
    btn.style.background = '#a2cfff';
    document.getElementById('keyInput').value = 'onanii';
    v4Section.style.display = 'none';
    keySection.style.display = 'block';
  }
  
  showToast(`已切换到 ${currentEngine.toUpperCase()} 引擎`, 'info');
}

// ============= V4 UI 和功能 ==================
function updateV4UI() {
    const legacyMode = document.getElementById('v4LegacyToggle').checked;
    const keySection = document.getElementById('key-section');
    const v4E2EKeys = document.getElementById('v4-e2e-keys');
    
    if (legacyMode) {
        keySection.style.display = 'block';
        v4E2EKeys.style.display = 'none';
        document.getElementById('v4EncryptInfo').textContent = 'V4传统模式使用文本密钥进行加密。';
    } else {
        keySection.style.display = 'none';
        v4E2EKeys.style.display = 'block';
        document.getElementById('v4EncryptInfo').textContent = 'V4端到端模式使用公钥加密。';
    }
}

async function generateV4KeyPair() {
    v4KeyPair = await crypto.subtle.generateKey(V4.ALGORITHM, true, ["encrypt", "decrypt"]);
    const publicKey = await crypto.subtle.exportKey("spki", v4KeyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", v4KeyPair.privateKey);

    document.getElementById('v4PublicKeyInput').value = arrayBufferToBase64(publicKey);
    document.getElementById('v4PrivateKeyDisplay').value = arrayBufferToBase64(privateKey);
    
    showToast('✅ 密钥对生成成功！', 'success');
}

async function downloadV4Key(keyType) {
    if (!v4KeyPair) return showToast('请先生成密钥对！', 'error');

    let keyBuffer;
    let fileName;
    if (keyType === 'public') {
        keyBuffer = await crypto.subtle.exportKey("spki", v4KeyPair.publicKey);
        fileName = 'moecipher_public_key.pem';
    } else {
        keyBuffer = await crypto.subtle.exportKey("pkcs8", v4KeyPair.privateKey);
        fileName = 'moecipher_private_key.pem';
    }

    const blob = new Blob([keyBuffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
    showToast('✅ 密钥文件已开始下载', 'success');
}

function uploadV4Key(event, keyType) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const buffer = e.target.result;
            if (keyType === 'private') {
                const privateKey = await crypto.subtle.importKey("pkcs8", buffer, V4.ALGORITHM, true, ["decrypt"]);
                v4KeyPair = { privateKey: privateKey, publicKey: v4KeyPair ? v4KeyPair.publicKey : null };
                document.getElementById('v4PrivateKeyDisplay').value = arrayBufferToBase64(buffer);
                showToast('✅ 私钥上传成功！', 'success');
            } else { // public
                const publicKey = await crypto.subtle.importKey("spki", buffer, V4.ALGORITHM, true, ["encrypt"]);
                v4KeyPair = { privateKey: v4KeyPair ? v4KeyPair.privateKey : null, publicKey: publicKey };
                document.getElementById('v4PublicKeyInput').value = arrayBufferToBase64(buffer);
                showToast('✅ 公钥上传成功！', 'success');
            }
        } catch (err) {
            showToast('密钥文件无效或类型错误！', 'error');
        }
    };
    reader.readAsArrayBuffer(file);
}

// 辅助函数
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// ============= 字符统计 ==================
function updateCharCount(text) {
  const count = text ? text.length : 0;
  document.getElementById('charCount').textContent = `字符数: ${count}`;
}

// ============= 自定义 Toast 提示 ==================
function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.className = 'toast ' + type;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2000);
}

// 初始化
updateCharCount('');
// 在页面加载时检查并加载seedrandom，用于V4引擎的随机数生成
(function() {
  const script = document.createElement('script');
  script.src = 'seedrandom.min.js';
  script.async = true;
  document.head.appendChild(script);
})();