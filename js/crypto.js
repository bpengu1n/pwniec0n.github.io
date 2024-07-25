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

// other helpers
async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Encrypted Content
//const ct_serial = "eyJzYWx0IjoiYzVzQUlYanoyWG03Ym9vTWRSbkZFQT09IiwiaXYiOiJpWXAzMWkwL3ZyMlR2SG1EIiwiY2lwaGVyIjoiQzBBYi9EVm1UNzdMNm5PMW9NeER3dVFtcTBDOXo3RkRXeXg1WmF4NnRycytZMXVZWTk1T0hmQ3QveCtIbCtlc0tPdmQvT1h1SzVsWFVSbzBRRlpvbVVMNi9FemR2dUVnS2VZN3E5QjZ0Q3dkd2FlcGswL0FYOWR0OUdTQ00rZEJycm94UmI0UTJEcUkyc0V4U3A3RmdBSGRLcVFUaE04Y3FLWDBkVUFiZ0xodjZmRkk0ZEpmK0VwQ2lZdmhmU3ZZNkRCSTVhN1BIbksyTUtFaDVDdENuSThNRkphVDNvY2xvTUNNckgwV0w4emZwdThjbmFrekFIREF6SGw2anFLSXRvcGloZndpazFpMEt3dmpvelBjcmgwMXMzazcvNTFUNVJSejQvWVV0em5CNGpoeHl6c1l1TTFVeElpNXdXNFhYTE14RXdNWFdydnJFRTBaYnpwYWphdTFQYUd4SEl0N2gzZit0b1d1MjZQVTBxYzBuZ1NnbDJNQWRXd2VSbGMxK2s2YVZGY29WcTgySFNTUXU2K3Nob0J2K3pHdEI4aitZQXlHbkkrSFFvd2R5b0RIclk2QmRxc3VuSVNpZ0xtYkdTU2tjRDAyYUN1Q0pXL3Y5WXUrK1FTalRoQ1haMWlxaDJtNmtDZkxXUWwvMWwraEd6MzVmVDg0WmJsSkRac3dkRE1qL2ZqcU9jSmpsd0pPRzV1Y05BVWNaaGw2YStPakpaRm1MV2NYMGdlbEwySjdLeWw0bHN1UHloMytvYkxBN21kTTdSWmhDZS8ySm44WEFKM3B3Z0k4ZzJNRUNsMkxrVEZGRW5ML2xkN3hMMGFNejY1UkxseXc2R2p6NFZaZmZZVDcrRWFNUjVSMG8zeDROR1ZRMWtBc1czbnpHanZnMGk0b3ZVTGVIWDdlMFpWU1gzVFpGWGIrVjNWWEZ1bXJQVnRPc2RqTE53RmZZdkw2YTRmUVZGa1k4ZWN1RlI3dUppUm02b1d0TTJuM004d3lkS2wrOU9DOTVsbkNNM2w4S0NaZE5YSFc2Ujh2T1h2bm1yNFMyOUlQTC9vbTlVL2kifQ==";
const ct_serial = "eyJzYWx0IjoiYlc1VUxqL3o1eEVBYzRWNnp3TjZqQT09IiwiaXYiOiJPQzRPVlJ5Y2NCaVhYajRTIiwiY2lwaGVyIjoib0lhdkdjMnlmYW1kUWtGUEoxUkFPcHl4WEJaOUQybXo0UE1ZRnpLeVhVTkJoeFpSS0FVRnVEZ3JXTzEvVGNKQXZ0STRQMmFWckNOc2UwQ09JTHhuK1VaY282TjFZMVhiWVJacDZSVlNsWmI1c1RGZGVKMFQ2V3VRMnlHTkpCT2ZtU1JEeEFHZ3BCcy9CQ2YvZTdhbXluRlFucXJva3RPQi9TejczekQ3UXFnOEI0d0duMmV2MlBoLzd3T1NGZFFUSDR0QXA3aHg2QU8weDJWcHE5TytXVCs2NnEyMW8zMHYzYTBnUi9pK29yc3dBcWIrRFhySUg2MGxmUys2QU1yRTRTUHIwVHBRUkRxdi92dW1YeXRrSFArQzFUUkZjL3E2ZjdsWklMemsyVlM3bmVmSnBxRmtpbzR0bkJVd1VYNGtLa2srL1FuSlozNjJNVzQ3alZabi9lOVN4N2RXNDBMK2d2elRyRHRqRy9uMEY4M3VZTiszMzdLUENRTmFUYzU5QkdCV3ZHYU9wNXJrNUtMaGs4eW1yWmZGRVRsL3FaVlVYM0lnSXJKVmtLZTZmSXhPTlRPaUpKZkZtVmtrbklqVnFmNk5QcmVDMHNxYW9JYUtvdHhUOURLQWhoQTZmSzJ0UHdwOGUrZUh2cUk2S2E5cHUrLzZvbXRVZFZjM3VxMWdMSHIyK2NSQ3hGbGN6TnVyUE5ObE9vbTBLUFVhOXB4cUhQZEwwcmFFZ0dEQVNwMHBpYkpld2JldG9ySzRoMjVHRkJPZmY3WVpWYytlZk5xcTI1TlljbmFONnM1RlJBekFEOWsrRkVNdHRUY29lRHRVQjMyVk9meHFMenlqTGNCN29SOW1SQU12VEcwR0V1STNGdDdsN3NHZkFNR1RGZGRDeVdmNTNYNkFJcVlhMEY3M0cyYnhTdXluYkNNREtDRzZVN2c4M3ZjeE5uVS94TS9rREpBdWdOU1dzQXNmdVZ5V3JkNzQ2by9mTnl6RXJETHpHMWRpT0lwTndlV2F5QzEvYjE1WEFoc0JpSHpFaHo0MERrOFQ5S01vdEpwOGt5aFpiZThESHFKSitaYlJnRzI4ZWU2cFY0MENCYk9tSkJDQ0w2V3cwT1lrdzBhUmRxTWJ6NEJtNVRqNEUyUVlKWEJjVy9RUm12eUZ3dzYrVFlPRDRHdEp0c0JneFdFSTc4ZFlSNVdnaTYxeVQzYldpM041VWpDb3UrOXFjeVZxL2VmakwxaWhSV28yWnRKMHZXdXorNnAwczkyTm1OOGx4cUlHZm0rcDUzeDNDSG82bHJoZHBLVUZBak83cVVJSy9NT3BwbVFXcFBvdWhmM2lDYXJ1S3Y4blVwRkpzSkdPSGE3V1pCbFZDSmZqTGNtbjdRRVFOazBVVldIUUhITDV3NlQzbThoY1hMdEpqUnVEQzZteGlEeHJSMEw2QUdlTU5UUjh6ZmRIQ3UzUlpQODloYno1VEJqRVN2OVdBZnA1eklXclkxL2I4eHFFcmNLLzQ2a0VESnUvQnJEOS9tL3F1c3lCR3BLSjdCMVlzcVRKbXBkeDd4VWNVTitVOGVYSkJGcm5QRTN6ek52VDA0cDFkSzE3QzQ4bXUwMExia0hUVXgrOU9tQUlUNmtkZCtTT2xoZElxb0NZWTdnaERyNmxsTDJ6aEFMbHE1cUhoeEliMUR4eEx2NFkzRUJLcmdhQ2JaZjN1ZFRSZW5MVDRXdTJ4QzlwcUcyUU01SWN5Z1MwcCthTGhxV3dMQlVMRmF1cEZxeDF0UVN2eGtUcHJmWDJ5QlM4ZUtlQ3YxMW9oQjdzUU43S2dQMENFQkF4bXBSV1RRbFRZdzFjUzhFcm9ES0QvaU0vL3d3WDl6ck8weTFTZTZaOXoyQk5uWVhDOVFaRGM3ZWg4V0xZNXpwMkR1anhrQmdhbGd5RXdvMlpyU3dRNCtoa2tQaVFWNnRGOElnU3Y2SkhvMzZTaTdQSHBKdHducU8xTDhHRUtrM0k1QVpkQ3hWOXFXSUt0RWVqMXd6cVNZeWNIN3hYaDdaTytnZ3FBd0Y4NEQzUTlrMnFyQ3JFenp6d0Z4WnJJYi9FSlNqbkdQaHFpV3lkcE0zL3hMUnpNSUhhRUpnc0luZ1kvUWVpVUF2RHF0dXBUOGxpRVdPeWVUN2dZa0RlVmFOM0c3dmlLQXRSS1JEVkYvUDNBYjV3dis0a3hDS0lMc1dMOW5NbS95OVprNEgxNm50QmZFUHNFd2NJeDl6dkR6TFpSMy84V0NKM2VJeDJydU8yU2xUb0ZuM0srK0dzSGVGZ0pDV29RVTZhMHZnemVZMkhiaXZNNk5TTTVzTjU3R0trOGFxVVRKeEgva1JQQ2JNZG85QzZMVTZrMFFwT1BlQlE3aWVZV2V0Uldsc29NazdaTlpySUUzYmJzUFFhbGo5dzFLMWZSOWt4cmpnUHV4TjNYRENSbkhncExVdUQ5Y1F6UUs2NnhDQWNNc2lJR2pyS1FiZjVjdkhWZGRLMit6UUdWekMyOFNQRk1JKzE4TU9iYnN3UGZTN3QxRSt0cG03WlErakM3MnRmNlBmbnBnU2QyQXZQSHpVVjJHZ29oZ08vdWE2VG1oSG9xUlpIdFZZdU5JbFB4bUxNT0pZZ1owVGtyVFRGV2JBVkI0MkhFM1BtRGZoNDltbmpmZzlPSVQxaTV6STIzT0lUN2tUbk5TRVA4WEk3aUswWlJQR0dpQm05aFpOQzZUYzRrUURIYTZ1QXJldmNmKytFRFBiZHZhNVcraWZWYkMvZis1R2xoMDJDVnozZE1tbVJ2SFUyc0VWWmt3WkhFWTk4Uk5nNFJzQ0c5SUdCbnFUSzhxN3ZlM1Z2SGd3anJZbVVyOEVuajkvZk9TMm5vMnN0Qmx2ZU1JUjhJbUx6YW1hc3BxYTRJZ3RQbGMyZlNaSDdYVTYxVEI0Z3BYNlVqbnRMcjMzYW9iZ0NFQnF6ZUxaajBTbVFqaWMxQ3FvdE96eGZ5YnUyRkdnRFpkVDBUWm9NQjJBMTZMMDNBN0d4Vyt0dFpsZVhpOWR4SktnWVpURWJHcDNvUDlScmpCM0k3MzNHS3g4V0hEKzdhajhTeHZCWGR1WEdFSmVGcXpSWW84OVMzNmxlZG5wMUZ1UGovbVlKWnc5Z1Z2alYrM2tIUGpJOVpzc0thY1E1ck5qSnBPelJ2QmVIanNMVVRPd2pseEVYYUxnVnJyVEFvR05WUVVLOHhlWlNVamhnNkNyZno1VVRweDZvNE5mZnlPaEYzU24xbnc4NzVrd2gyYUxoQkVuZ2lkRFBBZVROUW82bThCU1FxYkM5UjRycUFjZENXcnFidU9PelJkbTJuYmhSUk1XL041c2JPRnUxZmJGNEdQaTRLbmk0Qnk0VW9namVURmRrOTgyVzd3eVhYdjJHOVdQRTRDbE5JRHpiOHMzMVRTbk0vWkJNUGxTVVhxYnU1YTgzcEplaXd0eFM3d3IzWG5wbTBUR3hVaWhMRDBpUkZlK1Z6eUNZMUFsZkg2ektZWHlCM3h6YVFSaGN6eE00OGhuU2JFYXRJdE0wcDQxU1poSjJUallvL2FQT3IyZWNjQTJsMU42KzBjYnlYU0ZRanhNakk0NXBHMTU5alYwV0hTVGU2bTFHWTA5MWVBRCtVa1VzUzl2cmNnNE43aE43TkpsbGFHWlEwVW05Mk9wRjFiU1R6WjZZTzJGN1NqeUkrUEozUEF6S0NrNW9jUVhaOGY3djZodE5VN25xTzBJMS96cUZKejA4MjZxMjNEajJEZTBCMVpjY25QWkVycFRuQ3hwanl1WHNsOHJIOVZlRkNpSzVKOUFVKzZsZ3l3d28xb2txMkxQeWI1NEpjRWZBY2crMGdRN3Q1d1lyTzZKU2w4dW9qTUhwNFRETlRrL2d0ZGdCeHNOZjJuMlU5VURPdGd4TGoyeFptYWhDNURoQURwRDhNVDFkTDNNQ0RtYmxWVWtIMk00UlJYY3BHWS9VREQ3WkZTZzZjc3V5VHFYRUlsYWRDTlRHZEd1MXFPbHBLcWFhMGhJSG1uTDEvWkt5cHdEd1h5NnorUSttT2tEQ2M4d2hCVUJucWZjUEhPZWJBa05XZ2pTdVptTG5tTmZVYy9pOFNyNnArSVZFdllpUHFQVXN3c0ZQRWowSUF1NXJWVjJFUXpNQ1FZeHF1anM9In0=";
async function revealContent(inputPassword) {
  try {
    const ct = JSON.parse(atob(ct_serial));
    const decryptedText = await decrypt(ct, inputPassword); // Await the async function
    document.getElementById('contents').innerHTML = decryptedText;
    console.log(decryptedText);

    // Regular expression to match <script> tags and capture their contents
    const sre = /<script\b[^>]*>([\s\S]*?)<\/script>/gm;
    let m;

    // Iterate over all matches and capture the script contents
    while ((m = sre.exec(decryptedText)) !== null) {
      console.log(m[1]);
      eval(m[1]);
    }

    document.getElementById('password-input').classList.remove('error');
    document.getElementById('password-input').classList.add('success');
    await sleep(1000);
    document.getElementById('render-container').classList.remove('above');

    document.getElementById('password-container').classList.add('hidden');
    document.getElementById('logo').classList.add('small');

    // set the password cookie
    document.cookie = "password=" + inputPassword + ';samesite=strict';

  } catch (error) {
    document.getElementById('password-input').classList.add('error');
    console.error('Password incorrect');
    //alert('Password incorrect');
  }
}

// Set up the event handler
document.addEventListener('DOMContentLoaded', (event) => {
  const inputField = document.getElementById('password-input');
  /*const submitButton = document.getElementById('submit-button')*/

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
  /*submitButton.addEventListener('click', async function() {
    const inputPassword = inputField.value;
    await revealContent(inputPassword);
  });*/

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