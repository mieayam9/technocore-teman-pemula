'use strict';

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// did:key Ed25519 uses base58btc (z) and the two-byte varint for ed25519-pub.
function inspectDid(raw) {
  const text = raw.trim();
  if (!text) return {ok:false, message:'Isi DID publik terlebih dahulu.'};
  if (!text.startsWith('did:key:z')) return {ok:false, message:'DID Ed25519 untuk alur ini harus diawali did:key:z.'};
  const body = text.slice(9);
  if (!body || body.length > 60) return {ok:false, message:'Panjang data DID tidak sesuai.'};
  let n = 0n;
  for (const ch of body) {
    const digit = BASE58.indexOf(ch);
    if (digit < 0) return {ok:false, message:'Bagian setelah huruf z harus berupa Base58. Salin DID saja, tanpa fragmen atau tanda baca.'};
    n = n * 58n + BigInt(digit);
  }
  const bytes = [];
  while (n > 0n) {bytes.push(Number(n & 255n)); n >>= 8n;}
  for (const ch of body) {if (ch !== '1') break; bytes.push(0);}
  bytes.reverse();
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    return {ok:false, message:'Data tidak berformat Ed25519: harus memuat kode ed25519-pub dan 32 byte kunci publik.'};
  }
  return {ok:true, message:'Format Ed25519 cocok. Ini belum membuktikan kepemilikan DID.'};
}

if (typeof document !== 'undefined') {
  const form = document.getElementById('did-form');
  const input = document.getElementById('did');
  const result = document.getElementById('result');
  const clear = () => {result.textContent = ''; delete result.dataset.status; input.removeAttribute('aria-invalid');};
  form.addEventListener('submit', event => {
    event.preventDefault();
    const outcome = inspectDid(input.value);
    result.textContent = outcome.message;
    result.dataset.status = outcome.ok ? 'ok' : 'error';
    input.setAttribute('aria-invalid', String(!outcome.ok));
  });
  form.addEventListener('reset', clear);
  input.addEventListener('input', clear);
}

if (typeof module !== 'undefined') module.exports = {inspectDid};
