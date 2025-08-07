async function* sha256Generator(key) {
  const encoder = new TextEncoder();
  let data = encoder.encode(key);
  let hashBuffer = await crypto.subtle.digest('SHA-256', data);
  let hashArray = Array.from(new Uint8Array(hashBuffer));

  while (true) {
    for (let b of hashArray) {
      yield b;
    }
    let hashData = new Uint8Array(hashArray);
    hashBuffer = await crypto.subtle.digest('SHA-256', hashData);
    hashArray = Array.from(new Uint8Array(hashBuffer));
  }
}

const S = ['哦', '啊', '嗯', '咿', '咕', '哼', '呼', '唔', '齁', '喔'];
const P = ['～', '❤', '…', '！'];
const D = { '哦':0, '啊':1, '嗯':2, '咿':3, '咕':4, '哼':5, '呼':6, '唔':7, '齁':8, '喔':9 };
const Q = { '～':0, '❤':1, '…':2, '！':3 };

async function encrypt(text, key) {
  const gen = sha256Generator(key);  
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);
  const result = [];

  for (const b of bytes) {
    const next = await gen.next();   
    const e = b ^ next.value;
    const v = e >> 2;
    const s1 = S[Math.floor(v / 10)];
    const s2 = S[v % 10];
    const p = P[e & 3];
    result.push(s1 + s2 + p);
  }

  return result.join('');
}

async function decrypt(ciphertext, key) {
  if (ciphertext.length % 3 !== 0) {
    showToast('错误: 密文长度必须是3的倍数！','error');
    return '';
  }

  const gen = sha256Generator(key);
  const result = [];

  for (let i = 0; i < ciphertext.length; i += 3) {
    const a = ciphertext[i];
    const b = ciphertext[i + 1];
    const p = ciphertext[i + 2];

    if (!(a in D) || !(b in D) || !(p in Q)) {
      showToast('错误: 包含无效字符！','error');
      return '';
    }

    const v = (D[a] * 10 + D[b]) << 2 | Q[p];
    const next = await gen.next();  
    result.push(v ^ next.value);
  }

  try {
    const decoder = new TextDecoder();
    return decoder.decode(new Uint8Array(result));
  } catch (e) {
    showToast('错误: 密钥错误或密文已损坏！','error');
    return '';
  }
}

async function encryptText() {
  const input = document.getElementById('inputText').value.trim();
  const key = document.getElementById('keyInput').value || 'onanii';
  if (!input) {
    showToast('请输入要加密的内容！','info');
    return;
  }
  const result = await encrypt(input, key);
  document.getElementById('outputText').value = result;
}

async function decryptText() {
  const input = document.getElementById('inputText').value.trim();
  const key = document.getElementById('keyInput').value || 'onanii';
  if (!input) {
    showToast('请输入要解密的内容！','info');
    return;
  }
  const result = await decrypt(input, key);
  document.getElementById('outputText').value = result;
}

function copyResult() {
  const output = document.getElementById('outputText');
  if (!output.value) {
    showToast('没有内容可复制！','error');
    return;
  }
  output.select();
  document.execCommand('copy');
  showToast(' 已复制到剪贴板！','success');
}

// 输入输出对调：把输出内容移到输入框，清空输出
function swapIO() {
  const inputBox = document.getElementById('inputText');
  const outputBox = document.getElementById('outputText');

  const outputValue = outputBox.value.trim();
  if (!outputValue) {
    showToast('❌ 输出框是空的，无法对调！','error');
    return;
  }

  inputBox.value = outputValue;
  outputBox.value = '';
  showToast('✅ 已将输出内容移至输入框！','success');
}
function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.className = 'toast ' + type; 
  toast.classList.add('show');

  setTimeout(() => {
    toast.classList.remove('show');
  }, 2000);
}

const inputBox = document.getElementById('inputText');
const outputBox = document.getElementById('outputText');
const autoEncryptToggle = document.getElementById('autoEncryptToggle');

let debounceTimer;
function debounce(func, delay = 100) {
  return () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(func, delay);
  };
}

async function handleInput() {
  if (!autoEncryptToggle.checked) return;

  const text = inputBox.value.trim();
  const key = document.getElementById('keyInput').value || 'onanii';

  if (!text) {
    outputBox.value = '';
    return;
  }

  const isMeowCode = [...text].every(
    char => S.includes(char) || P.includes(char)
  ) && text.length % 3 === 0;

  if (isMeowCode) {
    const result = await decrypt(text, key);
    outputBox.value = result;
  } else {
    const result = await encrypt(text, key);
    outputBox.value = result;
  }
}

inputBox.addEventListener('input', debounce(handleInput));

autoEncryptToggle.addEventListener('change', () => {
  if (autoEncryptToggle.checked) {
    showToast('✅ 已开启实时加密/解密', 'info');
    handleInput(); 
  } else {
    showToast('⏸️ 实时模式已关闭', 'info');
  }
});
