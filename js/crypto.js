// based on: https://blog.elantha.com/encrypt-in-the-browser/

async function encrypt(content, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await getKey(password, salt);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const contentBytes = stringToBytes(content);

  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, contentBytes)
  );

  return {
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    cipher: bytesToBase64(cipher),
  };
}

let decrypt = async function (encryptedData, password) {
  const salt = base64ToBytes(encryptedData.salt);

  const key = await getKey(password, salt);

  const iv = base64ToBytes(encryptedData.iv);

  const cipher = base64ToBytes(encryptedData.cipher);

  const contentBytes = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher)
  );

  return bytesToString(contentBytes);
};

async function getKey(password, salt) {
  const passwordBytes = stringToBytes(password);

  const initialKey = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    initialKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// conversion helpers

function bytesToString(bytes) {
  return new TextDecoder().decode(bytes);
}

function stringToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToBase64(arr) {
  return btoa(Array.from(arr, (b) => String.fromCharCode(b)).join(""));
}

function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

function passwordHandler(event) {

  if (event.key === 'Enter') {

    // var pt = await decrypt(ct, document.getElementById("password-input").value);
  }
}

// Encrypted Content
const ct_serial = "eyJzYWx0IjoiYzVzQUlYanoyWG03Ym9vTWRSbkZFQT09IiwiaXYiOiJpWXAzMWkwL3ZyMlR2SG1EIiwiY2lwaGVyIjoiQzBBYi9EVm1UNzdMNm5PMW9NeER3dVFtcTBDOXo3RkRXeXg1WmF4NnRycytZMXVZWTk1T0hmQ3QveCtIbCtlc0tPdmQvT1h1SzVsWFVSbzBRRlpvbVVMNi9FemR2dUVnS2VZN3E5QjZ0Q3dkd2FlcGswL0FYOWR0OUdTQ00rZEJycm94UmI0UTJEcUkyc0V4U3A3RmdBSGRLcVFUaE04Y3FLWDBkVUFiZ0xodjZmRkk0ZEpmK0VwQ2lZdmhmU3ZZNkRCSTVhN1BIbksyTUtFaDVDdENuSThNRkphVDNvY2xvTUNNckgwV0w4emZwdThjbmFrekFIREF6SGw2anFLSXRvcGloZndpazFpMEt3dmpvelBjcmgwMXMzazcvNTFUNVJSejQvWVV0em5CNGpoeHl6c1l1TTFVeElpNXdXNFhYTE14RXdNWFdydnJFRTBaYnpwYWphdTFQYUd4SEl0N2gzZit0b1d1MjZQVTBxYzBuZ1NnbDJNQWRXd2VSbGMxK2s2YVZGY29WcTgySFNTUXU2K3Nob0J2K3pHdEI4aitZQXlHbkkrSFFvd2R5b0RIclk2QmRxc3VuSVNpZ0xtYkdTU2tjRDAyYUN1Q0pXL3Y5WXUrK1FTalRoQ1haMWlxaDJtNmtDZkxXUWwvMWwraEd6MzVmVDg0WmJsSkRac3dkRE1qL2ZqcU9jSmpsd0pPRzV1Y05BVWNaaGw2YStPakpaRm1MV2NYMGdlbEwySjdLeWw0bHN1UHloMytvYkxBN21kTTdSWmhDZS8ySm44WEFKM3B3Z0k4ZzJNRUNsMkxrVEZGRW5ML2xkN3hMMGFNejY1UkxseXc2R2p6NFZaZmZZVDcrRWFNUjVSMG8zeDROR1ZRMWtBc1czbnpHanZnMGk0b3ZVTGVIWDdlMFpWU1gzVFpGWGIrVjNWWEZ1bXJQVnRPc2RqTE53RmZZdkw2YTRmUVZGa1k4ZWN1RlI3dUppUm02b1d0TTJuM004d3lkS2wrOU9DOTVsbkNNM2w4S0NaZE5YSFc2Ujh2T1h2bm1yNFMyOUlQTC9vbTlVL2kifQ==";

async function revealContent(inputPassword) {
  try {
    const ct = JSON.parse(atob(ct_serial));
    const decryptedText = await decrypt(ct, inputPassword); // Await the async function
    document.getElementById('contents').innerHTML = decryptedText;
    console.log(decryptedText);
    document.getElementById('render-container').classList = '';

    document.getElementById('password-container').classList += ' hidden';
    document.getElementById('logo').classList += 'small';

    // set the password cookie
    document.cookie = "password=" + inputPassword + ';samesite=strict';

  } catch (error) {
    console.error('Password incorrect');
    alert('Password incorrect');
  }
}

// Set up the event handler
document.addEventListener('DOMContentLoaded', (event) => {
  const inputField = document.getElementById('password-input');
  const submitButton = document.getElementById('submit-button')

  // check if the password is stored in cookies
  if (document.cookie != null) {
    let cookies = document.cookie.split(';');
    cookies.forEach(element => {
      curCookie = element.split('=');
      if (curCookie[0] === 'password') {
        revealContent(curCookie[1]);
      }
    });
  }

  // submit button event listenr
  submitButton.addEventListener('click', async function() {
    const inputPassword = inputField.value;
    await revealContent(inputPassword);
  });

  // Input field event listener
  inputField.addEventListener('keydown', async function (event) {
    if (event.key === 'Enter') {
      const inputPassword = inputField.value;
      await revealContent(inputPassword);
    }
  });

  inputField.addEventListener('input', () => {
    submitButton.disabled = !(inputField.value.length > 3);
  });
});