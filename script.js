// ================== Seedrandom Library (Embedded) ==================
!function(f,a,c){var s,l=256,p="random",d=c.pow(l,6),g=c.pow(2,52),y=2*g,h=l-1;function n(n,t,r){function e(){for(var n=u.g(6),t=d,r=0;n<g;)n=(n+r)*l,t*=l,r=u.g(1);for(;y<=n;)n/=2,t/=2,r>>>=1;return(n+r)/t}var o=[],i=j(function n(t,r){var e,o=[],i=typeof t;if(r&&"object"==i)for(e in t)try{o.push(n(t[e],r-1))}catch(n){}return o.length?o:"string"==i?t:t+"\0"}((t=1==t?{entropy:!0}:t||{}).entropy?[n,S(a)]:null==n?function(){try{var n;return s&&(n=s.randomBytes)?n=n(l):(n=new Uint8Array(l),(f.crypto||f.msCrypto).getRandomValues(n)),S(n)}catch(n){var t=f.navigator,r=t&&t.plugins;return[+new Date,f,r,f.screen,S(a)]}}():n,3),o),u=new m(o);return e.int32=function(){return 0|u.g(4)},e.quick=function(){return u.g(4)/4294967296},e.double=e,j(S(u.S),a),(t.pass||r||function(n,t,r,e){return e&&(e.S&&v(e,u),n.state=function(){return v(u,{})}),r?(c[p]=n,t):n})(e,i,"global"in t?t.global:this==c,t.state)}function m(n){var t,r=n.length,u=this,e=0,o=u.i=u.j=0,i=u.S=[];for(r||(n=[r++]);e<l;)i[e]=e++;for(e=0;e<l;e++)i[e]=i[o=h&o+n[e%r]+(t=i[e])],i[o]=t;(u.g=function(n){for(var t,r=0,e=u.i,o=u.j,i=u.S;n--;)t=i[e=h&e+1],r=r*l+i[h&(i[e]=i[o=h&o+t])+(i[o]=t)];return u.i=e,u.j=o,r})(l)}function v(n,t){return t.i=n.i,t.j=n.j,t.S=n.S.slice(),t}function j(n,t){for(var r,e=n+"",o=0;o<e.length;)t[h&o]=h&(r^=19*t[h&o])+e.charCodeAt(o++);return S(t)}function S(n){return String.fromCharCode.apply(0,n)}if(j(c.random(),a),"object"==typeof module&&module.exports){module.exports=n;try{s=require("crypto")}catch(n){}}else"function"==typeof define&&define.amd?define(function(){return n}):c["seed"+p]=n}("undefined"!=typeof self?self:this,[],Math);

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

// ================== MoeCipher V4 (ECC E2EE & Legacy) ==================
const V4 = {
    SOUND_CHARS: ['哦', '啊', '嗯', '咿', '咕', '哼', '呼', '唔', '齁', '喔'],
    PUNCTUATION_CHARS: ['～', '❤', '…', '！'],
    SOUND_DECODE_MAP: { '哦':0, '啊':1, '嗯':2, '咿':3, '咕':4, '哼':5, '呼':6, '唔':7, '齁':8, '喔':9 },
    KEY: 'onanii',
    CHECKSUM_LENGTH: 4,
    E2E_ALGORITHM: { name: "ECDH", namedCurve: "P-384" },
    SYMMETRIC_ALGORITHM: { name: "AES-GCM", length: 256 },
    IV_LENGTH: 12,
    EPHEMERAL_KEY_LENGTH: 97 // 1 (tag 0x04) + 48 (x) + 48 (y) for P-384
};


async function v4_sha256(data) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

// --- V4 Encoding and Rhythm (Moe String Conversion) ---

function v4_bytesToMoe(bytes) {
    if (bytes.length === 0) return '';

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
    while (bigInt > BigInt(0)) {
        base10Representation = V4.SOUND_CHARS[Number(bigInt % BigInt(10))] + base10Representation;
        bigInt /= BigInt(10);
    }
    return zeroPrefix + (base10Representation || V4.SOUND_CHARS[0]);
}

function v4_moeToBytes(moeString) {
    const cleanMoeString = moeString.split('').filter(char => char in V4.SOUND_DECODE_MAP).join('');
    if (!cleanMoeString) return new Uint8Array(0);
    
    let zeroPrefixLength = 0;
    while (zeroPrefixLength < cleanMoeString.length && cleanMoeString[zeroPrefixLength] === V4.SOUND_CHARS[0]) {
        zeroPrefixLength++;
    }

    const nonZeroString = cleanMoeString.slice(zeroPrefixLength);

    if (nonZeroString.length === 0 && zeroPrefixLength > 0) {
        const bytes = new Uint8Array(zeroPrefixLength);
        bytes.fill(0);
        return bytes;
    }

    let bigInt = BigInt(0);
    for (const char of nonZeroString) {
        bigInt = bigInt * BigInt(10) + BigInt(V4.SOUND_DECODE_MAP[char]);
    }
    
    const byteList = [];
    while (bigInt > BigInt(0)) {
        byteList.push(Number(bigInt & BigInt(0xFF)));
        bigInt >>= BigInt(8);
    }
    
    const result = new Uint8Array(zeroPrefixLength + byteList.length);
    result.fill(0, 0, zeroPrefixLength);
    result.set(byteList.reverse(), zeroPrefixLength);
    return result;
}

function v4_add_rhythm(moeSoundString, key) {
    const rng = new Math.seedrandom(key);
    const result = [];
    let sourceChars = moeSoundString.split('');

    while (sourceChars.length > 0) {
        const phraseLen = Math.floor(rng() * 5) + 2; // 2-6
        let phrase = '';
        for (let i = 0; i < phraseLen && sourceChars.length > 0; i++) {
            phrase += sourceChars.shift();
        }
        if (phrase) {
            const punctuation = V4.PUNCTUATION_CHARS[Math.floor(rng() * V4.PUNCTUATION_CHARS.length)];
            result.push(phrase + punctuation);
        }
    }
    return result.join('');
}

// --- V4 Traditional (Symmetric Keystream) Encryption ---

async function* v4_keystream_generator(key) {
    const encoder = new TextEncoder();
    let seed = await v4_sha256(encoder.encode(key));
    while (true) {
        for (const byte of seed) yield byte;
        seed = await v4_sha256(seed);
    }
}

async function v4_crypt_data(data, keystream_key) {
    const keystream = v4_keystream_generator(keystream_key);
    const resultBytes = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
        resultBytes[i] = data[i] ^ (await keystream.next()).value;
    }
    return resultBytes;
}

// --- V4 E2E (ECC) Core Functions ---

async function v4_encrypt_e2e(text, recipientPublicKey) {
    const plaintextBytes = new TextEncoder().encode(text);
    const checksum = (await v4_sha256(plaintextBytes)).slice(0, V4.CHECKSUM_LENGTH);
    const dataWithChecksum = new Uint8Array(checksum.length + plaintextBytes.length);
    dataWithChecksum.set(checksum);
    dataWithChecksum.set(plaintextBytes, checksum.length);
    const compressedData = pako.deflate(dataWithChecksum, { level: 9 });

    const ephemeralKeyPair = await crypto.subtle.generateKey(V4.E2E_ALGORITHM, true, ["deriveKey"]);
    const sharedSecret = await crypto.subtle.deriveKey({ name: V4.E2E_ALGORITHM.name, public: recipientPublicKey }, ephemeralKeyPair.privateKey, V4.SYMMETRIC_ALGORITHM, true, ["encrypt"]);
    
    const iv = crypto.getRandomValues(new Uint8Array(V4.IV_LENGTH));
    const encryptedData = await crypto.subtle.encrypt({ name: V4.SYMMETRIC_ALGORITHM.name, iv: iv }, sharedSecret, compressedData);
    const ephemeralPublicKeyRaw = await crypto.subtle.exportKey("raw", ephemeralKeyPair.publicKey);

    const combinedData = new Uint8Array(ephemeralPublicKeyRaw.byteLength + iv.byteLength + encryptedData.byteLength);
    combinedData.set(new Uint8Array(ephemeralPublicKeyRaw), 0);
    combinedData.set(iv, ephemeralPublicKeyRaw.byteLength);
    combinedData.set(new Uint8Array(encryptedData), ephemeralPublicKeyRaw.byteLength + iv.byteLength);

    const moeSoundString = v4_bytesToMoe(combinedData);
    return v4_add_rhythm(moeSoundString, 'e2e' + Date.now());
}

async function v4_decrypt_e2e(ciphertext, privateKey) {
    const combinedData = v4_moeToBytes(ciphertext);
    if (combinedData.length < V4.EPHEMERAL_KEY_LENGTH + V4.IV_LENGTH) throw new Error("密文无效：数据过短");

    const ephemeralPublicKeyRaw = combinedData.slice(0, V4.EPHEMERAL_KEY_LENGTH);
    const iv = combinedData.slice(V4.EPHEMERAL_KEY_LENGTH, V4.EPHEMERAL_KEY_LENGTH + V4.IV_LENGTH);
    const encryptedData = combinedData.slice(V4.EPHEMERAL_KEY_LENGTH + V4.IV_LENGTH);

    const ephemeralPublicKey = await crypto.subtle.importKey("raw", ephemeralPublicKeyRaw, V4.E2E_ALGORITHM, true, []);
    const sharedSecret = await crypto.subtle.deriveKey({ name: V4.E2E_ALGORITHM.name, public: ephemeralPublicKey }, privateKey, V4.SYMMETRIC_ALGORITHM, true, ["decrypt"]);
    
    let compressedData;
    try {
        compressedData = await crypto.subtle.decrypt({ name: V4.SYMMETRIC_ALGORITHM.name, iv: iv }, sharedSecret, encryptedData);
    } catch (e) {
        throw new Error("解密失败：私钥错误或密文已被篡改。");
    }

    const decompressedData = pako.inflate(new Uint8Array(compressedData));
    if (decompressedData.length < V4.CHECKSUM_LENGTH) throw new Error("解密失败：密文数据不完整，缺少校验码。");

    const receivedChecksum = decompressedData.slice(0, V4.CHECKSUM_LENGTH);
    const plaintextBytes = decompressedData.slice(V4.CHECKSUM_LENGTH);
    const expectedChecksum = (await v4_sha256(plaintextBytes)).slice(0, V4.CHECKSUM_LENGTH);

    if (receivedChecksum.join(',') !== expectedChecksum.join(',')) {
        throw new Error("校验失败：密文数据已被篡改或密钥错误。");
    }

    return new TextDecoder().decode(plaintextBytes);
}

// --- V4 Legacy (Symmetric) Core Functions ---
async function v4_encrypt_legacy(text, key = V4.KEY) {
    const plaintextBytes = new TextEncoder().encode(text);
    const checksum = (await v4_sha256(plaintextBytes)).slice(0, V4.CHECKSUM_LENGTH);
    const dataWithChecksum = new Uint8Array(checksum.length + plaintextBytes.length);
    dataWithChecksum.set(checksum);
    dataWithChecksum.set(plaintextBytes, checksum.length);
    const compressedData = pako.deflate(dataWithChecksum, { level: 9 });
    const encryptedBytes = await v4_crypt_data(compressedData, key);
    const moeSoundString = v4_bytesToMoe(encryptedBytes);
    return v4_add_rhythm(moeSoundString, key);
}

async function v4_decrypt_legacy(ciphertext, key = V4.KEY) {
    if (!ciphertext) return "";
    const encryptedBytes = v4_moeToBytes(ciphertext);
    if (encryptedBytes.length === 0) throw new Error("密文无效：不包含任何有效的声音字符。");
    const compressedData = await v4_crypt_data(encryptedBytes, key);
    
    let decompressedData;
    try {
        decompressedData = pako.inflate(compressedData);
    } catch (e) { throw new Error("解密失败：密钥错误或密文已损坏。"); }

    if (decompressedData.length < V4.CHECKSUM_LENGTH) throw new Error("解密失败：密文数据不完整，缺少校验码。");

    const receivedChecksum = decompressedData.slice(0, V4.CHECKSUM_LENGTH);
    const plaintextBytes = decompressedData.slice(V4.CHECKSUM_LENGTH);
    const expectedChecksum = (await v4_sha256(plaintextBytes)).slice(0, V4.CHECKSUM_LENGTH);

    if (receivedChecksum.join(',') !== expectedChecksum.join(',')) {
        throw new Error("校验失败：密钥错误或密文数据已被篡改。");
    }
    
    return new TextDecoder().decode(plaintextBytes);
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
            const legacyMode = document.getElementById('v4LegacyToggle').checked;
            if (legacyMode) {
                const key = document.getElementById('keyInput').value || V4.KEY;
                result = await v4_encrypt_legacy(input, key);
            } else {
                const publicKeyText = document.getElementById('v4PublicKeyInput').value.trim();
                if (!publicKeyText) return showToast('E2E模式需要输入对方的公钥！', 'error');
                const keyBuffer = base64ToArrayBuffer(publicKeyText);
                const publicKey = await crypto.subtle.importKey("raw", keyBuffer, V4.E2E_ALGORITHM, true, []);
                result = await v4_encrypt_e2e(input, publicKey);
            }
        }
        document.getElementById('outputText').value = result;
        updateCharCount(result);
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
                    return showToast('E2E模式需要先生成或上传您的私钥！', 'error');
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

let debounceTimer;
function debounce(func, delay = 250) {
    return (...args) => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => { func.apply(this, args); }, delay);
    };
}

const debouncedEncrypt = debounce(encryptText);
document.getElementById('inputText').addEventListener('input', () => {
    if (document.getElementById('autoEncryptToggle').checked) {
        debouncedEncrypt();
    }
});
document.getElementById('autoEncryptToggle').addEventListener('change', () => {
    if (document.getElementById('autoEncryptToggle').checked) {
        showToast('✅ 实时模式已开启', 'info');
        encryptText();
    } else {
        showToast('⏸️ 实时模式已关闭', 'info');
    }
});

function switchEngine() {
    const btn = document.getElementById('engineToggle');
    const v4Section = document.getElementById('v4-section');
    const keySection = document.getElementById('key-section');
    const engines = ['v1', 'v3', 'v4'];
    const currentIdx = engines.indexOf(currentEngine);
    currentEngine = engines[(currentIdx + 1) % engines.length];

    if (currentEngine === 'v1') {
        btn.textContent = '🔄 使用 V1 引擎';
        btn.style.background = '#a2cfff';
        v4Section.style.display = 'none';
        keySection.style.display = 'block';
    } else if (currentEngine === 'v3') {
        btn.textContent = '♿ 使用 V3 引擎（文本压缩）';
        btn.style.background = '#4caf50';
        v4Section.style.display = 'none';
        keySection.style.display = 'block';
    } else { // 'v4'
        btn.textContent = '🔒 使用 V4 引擎（ECC E2EE）';
        btn.style.background = '#e76f8e';
        v4Section.style.display = 'block';
        updateV4UI();
    }
    document.getElementById('keyInput').value = 'onanii';
    showToast(`已切换到 ${currentEngine.toUpperCase()} 引擎`, 'info');
}

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
        document.getElementById('v4EncryptInfo').textContent = 'V4端到端模式使用ECDH+AES-GCM。请将您的公钥发给对方，并输入对方的公钥来加密消息。';
    }
}

async function generateV4KeyPair() {
    try {
        v4KeyPair = await crypto.subtle.generateKey(V4.E2E_ALGORITHM, true, ["deriveKey"]);
        const publicKeyRaw = await crypto.subtle.exportKey("raw", v4KeyPair.publicKey);
        
        document.getElementById('v4PublicKeyInput').value = arrayBufferToBase64(publicKeyRaw);
        document.getElementById('v4PrivateKeyDisplay').value = '您的私钥已在内存中准备就绪。为安全起见，请点击下方按钮下载备份。';

        showToast('✅ 密钥对生成成功！', 'success');
    } catch (e) { showToast('密钥生成失败: ' + e.message, 'error'); console.error(e); }
}

async function downloadV4Key(keyType) {
    if (!v4KeyPair && keyType === 'private') return showToast('请先生成密钥对！', 'error');

    try {
        let blob, fileName;
        if (keyType === 'public') {
            const publicKeyText = document.getElementById('v4PublicKeyInput').value;
            if (!publicKeyText) return showToast('请先生成密钥对！', 'error');
            blob = new Blob([publicKeyText], { type: 'text/plain' });
            fileName = 'moecipher_public_key.txt';
        } else {
            const privateKeyJwk = await crypto.subtle.exportKey("jwk", v4KeyPair.privateKey);
            blob = new Blob([JSON.stringify(privateKeyJwk, null, 2)], { type: 'application/json' });
            fileName = 'moecipher_private_key.json';
        }

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast(`✅ ${keyType==='public'?'公钥':'私钥'}文件已开始下载`, 'success');

    } catch (e) { showToast('密钥导出失败: ' + e.message, 'error'); }
}

function uploadV4Key(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const keyJwk = JSON.parse(e.target.result);
            if (!keyJwk.d) throw new Error("文件不是有效的私钥 (JWK 格式)。");

            const privateKey = await crypto.subtle.importKey("jwk", keyJwk, V4.E2E_ALGORITHM, true, ["deriveKey"]);
            v4KeyPair = { privateKey: privateKey, publicKey: null };

            document.getElementById('v4PrivateKeyDisplay').value = '您的私钥已成功上传并准备就绪。';
            showToast('✅ 私钥上传成功！', 'success');

        } catch (err) {
            showToast('密钥文件无效或类型错误！' + err.message, 'error');
            console.error(err);
        }
    };
    reader.readAsText(file);
    event.target.value = ''; // Reset file input
}

// 辅助函数
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
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

function updateCharCount(text) {
    document.getElementById('charCount').textContent = `字符数: ${text ? text.length : 0}`;
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = 'toast ' + type;
    toast.classList.add('show');
    setTimeout(() => { toast.classList.remove('show'); }, 2500);
}

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    updateCharCount('');
    const uploadInput = document.getElementById('uploadPrivateKey');
    if(uploadInput) {
        uploadInput.setAttribute('accept', '.json'); // For private key
    }
});