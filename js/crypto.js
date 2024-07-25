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
const ct_serial = "eyJzYWx0IjoiVTJQcGpXemhXMyt6THY1ZDZZVDAyQT09IiwiaXYiOiJZRmVzYzZpNnFLOERpM1QzIiwiY2lwaGVyIjoiVUcyQVA1b1drQzRHanB3aXJPQTQ2Q2liM1VzZEhpOGNzOFZUcE1vd2RieFExeElVZmdkM2FkZnlOUEdFbE8vRXBmempFN3hsUExrY2FhdDRsYVdCU0htTE5Jb2pqcjNoK1BBYVQ0LzdDM2dINTRWWHcwQWxMSis1MlBFYlg4OVVnNkZna1NsakhiWDU3N1NQNEZtTXpkVlNlWnFKV0REcTJnb1YzQlZOaTRlYjRsQWlyZHVwalVKWG8xRlpINVc2U2doZURTS3BVSnZaajdabjVLWTRJNURudXh3SUZjc3pSN05PMUoyc1NRamhvU1RsV3laYy93aWhvV2JGUUt3c2hCQ05RZ2hnbDJnMGpTYlBTWCtsNVIrTDZ5M0xMQ0czMlNjVWE3TlVRRWFTS01ybWZjWU82TDk3RHBmL3IwalZEVWI5Mjh0dFloeERGbFBjelFYdFc0S3dEbCt0M1l6VDVNRWM3eDVZcVFTb1ZrbXM1NkVRWDFOUm5KZit2QlQ3dG5yRzB6K080VWVuVlBXOVk1ZHRsQVVwbWgzb2RHUEJhVDhzVlJOenB1M2JhTUtCTXN6Y1c0cnJEanRsaVZDR1pWOUF0Nm1oY1N0ajRiTHdoVzcwR0NSWkF2UkhOUmhRL3NWa1gyb0RlS1A0Q1Z1UWtYNXJ6Smwwd1N4aUpzckN2WlA2Y1BaRXFpYXl2TFJDbzg1dnYwdGgyT20veXAyMEVnYWswdWZYbXN4M3MyZkFOakNNZit1OWF3Q1daSWNFRjM3Zzc5QWRhaU9XQ0czSGNyQ3lMSHlpY1Y3THNIV21DZjhnejFmOGZPd1dnY2xuaHFtMEFHZUFGaGxSbFdpc3VpVU9SZ29pdkZDYStBM004NGxjdEoxL0F6ZEM0cFExbXgveERlcVI4YzZUUnZreXBiUHl6cEhFSElSRlI3SEFHdVJMNDZWVklTWmVxQmRieFUwL0lOU3J1dWs1NUZOZGlwQW9mOFc5T2xlN2QreTNTNi9pamdnK0JKV3BNNjliMG1WL1p6WWpBYUQwSVBoV3FtSldCaFYremRrTGtsUHVTM1lUbHNQNG5lczRaRTIzZHQxZTJlaXBmVjJOQzVYeitZL3lyNmZBMUFGeFV3cUpCSURReXdzYkZXcVlBTGNiU3k1Zml6cThMa1RPSTZNMTdPaWFJQUIvazMyb29sZk9MNC9ZVGRJS0ZHc1lJNFdValJENU91SnJhQmNxVkk1YXcwbzBvNGQ0LzczRCtvNStDNkZEZDJmd2hsY0pSU3pNWmFEOVplMUNOR0ZhckFmVmhXc1Q5ZytOL1QzTnlsell0Z2VaMXpZZjAzQVhtMDhZekpNeUs3cDQrQTNDdHpkeENTSU1kWXlESlB3VTk1bDZzeUxIS3lqWGI3Z0MrakQrZHBUeHhiSW8yajBsQzFMcDBZTVRUWllyT3FDYjY2M3IyaEYxRHVzWm16M056NDVYTXdQUklQbmpsdXQ0RnBMc2NadjVDa0s4TXlmRk5tRFVURDhwQWVwSjFoNnJHYk4wbEJuWlppWmRNWlN4VG1IV0MvbktQWjZobzBxUGFCQ1NvNXI4bkhVd0drK2tMQ0VteWZtUGpqbjAyQkxDbGJVMkJhcWdJRmNnaEp4WjFJRXFmTzIxdytpV1A1d2hyZ3F1M0p2THJrMVVCeEk4OG1TanlOVVNwU1llQ21wNkw2SUY2RWZHckZ3eHd2NmRVK25BK1pUQy93cVFvZW9XN2l0QVdZS25WaEFaNmRCSTQ0bCtlNytvS25xVUpadVNmQVBYN3paQXZVSzFFbnRUQ0ExdlQycVlzcFJ4N05Tb3lCcDBtbjlVcUdRYXltRTlmbnZwcnIrLy9JS0ZkRzZkanBGMEs3Z3pxUmsySTk1U3F0cllucE01T3ZTNHIzeWxpdnpkeXhFR1JubEc3ZDZOMVA1RFJjZEhYOFpvVWRNcUJtbG5PbEFIS090ZVk1aVFQcGFCakJwRzlaVkpOc1p2dVArWENUWkQzeFhhWENEOXI0czJrYWIrOHpOZmw0MnZKdnBVL2I4Ty92eUk0S1JTcmxYN2lVYkJYYU1kMlc0YmdTOGNCc2ZwSGtBMTJlcDBWUVEyd1VJMlUyM2hGRUdMOVBEQU0vaDZxOUN3M2UvbjJVWmhoYTAvNXp1KzUvcGRuU2pSd1U3WGM3N3NEd0hTSERMME1PZ0xqOXU2R2N0RlRvUEgvS3VLQzFFQ2tKRVl1YVREVlUycGR4Q2lMRU5Mc01UN0xwS01TNmxDaGFhTXpHd29Nc2JLQW5FdVlVN3JRcDIvUG83SGUzZTBHYnZDbW4zVjNTcW5JWEMwR2ppSjVwWGhWaks2L0lyS2xrMlRMUkRteW5oMXh2ZStRblZETHpWRUVtQ2dSVmtwMFFIdjN1VVA1Nk9vcUMyZnRSTWdMUUk1RURRMWpKS2V5aTBOMFdUSjNWSWlqUlV3YW9ScVBXU3g0R2IwUEs5RVFNMVFLbDFwUlF6c3Q1SHFrWUFHL0o1QnZXUXNqMW4ydUU4UmdqWDBnQWd4SDNwWnhlVXR6NUJCeEtUTmFVeDBOSUVIQ0RJVjlLMXFvWHR1b0tEK2FuYXRlK0tITGhrOUFUdUZrYXBGeUtRRlR4Qjk4akhYVjhqTmp5dmNGQ3ZZWW80cHBzMzJkYyt2eDVzUHpIRkthdVFWWGRrOThOc2kycU95ekFtZXZHTXNIQXVXc0hkaHV1L3dqL0hqeERjNzdkQS9zT29sRTRESnBISWxoZDJWZG9VNG9WaStBSmR1dzE1djc1UStyL1BYSzd4K0xOdDdaSlNSZ0NDTVo5WU9pbXBRMGxWSkI0bys4WE1NN3hMcUNlalEyM25CUmVQdDhFK2p4YjdQZjU1YnVMMGl5TE9LL09tcWlLbVNUTVFVbWRaVDdEckowazVnK2pKN3I5WVN2SDVtejRENStuMzQ4N2x3RG1saFMzNFN4TDNWMzE0UG9wcFN0YWpSWnlMYkNBPT0ifQ==";

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
      var ns = document.createElement('script');
      ns.innerHTML = m[1];
      document.head.appendChild(ns);
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