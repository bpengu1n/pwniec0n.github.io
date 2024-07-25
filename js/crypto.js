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
const ct_serial = "eyJzYWx0IjoidVA0SWNQWnJyVWY5eElFa25sbnQrUT09IiwiaXYiOiJFUlZZa0pYd0JteldVYVIvIiwiY2lwaGVyIjoid2praXoxbURTVUR5RFhuVzVqaXIzeVNMcEZOT1hwNE5qL1QxWm55ZTloaHVVL2dpNExpa1dQVmg4L2JVR1V1QnpBV3pFZC8rWi9xb001R2t4TnA0TWE2TG1pN0FBZWp2a25UVzF1QnRsY0EzUEVTZEhkU0ZHUFpsNkxZeUJ5RFF0dm1mVEVyc1hOMTQ1REpGcy8wSG91WklPSmJ2ZVBKWHViNk83Q3E2bGU2djZvdkZQZWdSMEIzM1N2RFdNNmVUUjdRckh2ZnBLUG50VUhsTjFTUGxjMlI3VDZVQlVNTmczRm92Wk1UM0ZqNEhiTzNmNzdITmxHYjVBTUNuNXB0bVdpRTVHUWhxZytBOFdyS2lKMXNRek5sck81UHI1TjB2QmFtMHZnNHEzSStGWXpjcHQ2cjNPNC9aOHNZL0lSWng0eFN2V1NHU0hXekVOK1pXSjB6QkxpRFI1UTgweU9mcHk0Y05WaUxlVTFQd3NpaENUbmt5cEo1TURzVmJtRjJKeWxld1ZBcXE5QlM5dkxsWGpFTG1IdklQcDFvZVMvZlZRVG4wSW00dExZcGR2SzdJZjlyc2l0WWN1YWg0bUJRcUJJSkRQaXI0WnhJM2hPZWJYM2tEeWdIb0wrL1l5UnlTK1Q5aFg2QzErS2w5c2FES1pUL2d1QUhTL0lvNFNoMjMvU3NDb1NpYndEeTJqeHFFdDZIU3dmTkNoZ2dUdm1kckM1TG96YUlZd2FqR3k1OWtjWmFrYVdObTZ2Z21OdFR3Qk5yU0FpRVQ3b1hYRnFkZ1p2QjR4M2VsVXpwK3ZsMStNTEttNGRVZmNYTWx3Q3diaUEwVGNCcFkvczd2REZsLzQzVWtiVmpFdmJ0ZXB4R3lEaXRMYkhDWHNCSHIwQmRSZEh0YjRBNFNCb2hwNjNkM25GYlhCZFA3Z0xqbHdqV1hZTkhrdjdjeGJwRUdzUjFSVUJhVUNXV21wOHB5RGVUb3ZpZE5uNXJaRVZ2cTlwWG1Ga0FkRTdpZ09OSU0wa3ljbUpmQ2pSREhFMWQrQzFKbkYwWUVRY0lJNy8vdzhEcmVPMGdBbHBtcmlhMVpaVjl6S0lzUEZIanJOOWVYdlM1MFptSU5GaTIwM0ZLcU8xV1k2VFBOSnBqdDgrNzZ1Z0czYm5VcW1qL213ZFRNamFURFZKcnhIL1A0TFB3VXJCNG16bEFKM1JrZWNKZGZKK3FIWDhMQ2dONW5oNGdSNmw5eHFpL2loRXNMS3crRU1Ta0IvNlJvVyt6QkFSQ2dhSlNyNitFUE1CdXpTT3A5citHWWJRVUV4a1BoV1hPWEgzOFBaNkc4RUV2a3BGKzBscnZMMVkyNVlDOHNNRnlIRTJZLy9RakN0ODZja1ByajJxUXFpRkxkQzlTUVBnRUdVdG1UWk8yUlFaYXZ1c2p6aDZhOXVLTmg1T0NObzdSMG1nbjJzdW1KN3pZVGVDUEhPemNqYTBDR2VtYTJ2bjhVWGRIZGQzR0xHSEg5ZEIrZU95NTFFeUFkcXp4dXNMLzlwdGlZL290L2xrSHc0QlZkNUNTQU40akRMTEFGY3JrSjJ6Skkwb25JVFN4clkrMlF4OVdMbElqaTBSditKd2g0ZEpzNS9sVkREREFJK09oaFNsYWJBSkpiVlhNVG5RWDEwdURLdEFWSThtVXFadjkwZEhGZU0rZGxOZmxXTVRCM0VUVW9DME83aWR2YkprZTRYdmM5c2I4NFhPdUtnNlh3blBXS3YyY3hCSk5jSGRkTHh6aGdQeXVqTGtvWmY1cFhtTWF4S3BncWtOZWI5a3NzQ0dodEI1djIyU0VESlp0L3NBNExocjFFVGdQY25Nbm0ranZWN0xMdTBOSkhYbTA3am1lT3VmRzZJOG1pSHZDbGlzeDE1b3NUUlplZUcveTBYN2NHa1R5bUxmMHNDc1FRRDMwQUo1REpnOHV5V1FKcXo1c3ZKZVI1c1l5VGlqZ3NvUFl2N21BZENZd0xMZHVPTHoyZ3lPenpJQmczcVJJUVZ0OWcyM21XM1hxMGxpb3NjRzVCL04veHVWQlg0ak1YRnBBTjNJV0N6alRIK21lUkNEbS9HMGFDS1pPMk5BL2xDNnRzdTVXbXg1WUo4aSt6K2w3YkxraUY3c0RyblhpZnluNS9BTHhxbWZLNGFDUlRQcXNRdXhNWUZsY0tZZTdLUEMrS25FZUVGL3YvQlJoeWdyN1IzWHdwU2tqZnl6RDNyL0xzRmZCWkJEVU9WL21HU2hDazJnWFBNVEpFZHZtL25qTU9GU1JnMFhDSjRXanZNbW0vQmh1Ym1BTVV5QlFzdm9zVzlaNFI2UjNkcGEvNGFXZ3NxRzgrYitaT1hZQUY0bFNtTmlxdExGNWtySkNGTXFTaW9ydExGelZHc2NISklCaE4zdXVuK1YvVmcyOVIwMXJ1VVpFVnRoaGROMWJlT0g5RDZDdXJzanZ0ck51cnJGMVQ1VE9ybEFkaDVzTUhJZlJDU05NQjVrMWZSOUlLSXhjeWxsWUNUcFd0WFdTcFAyazRIOG53dVZtcXJTQ0krdE1ONGZxb2U0ajg4UnVBSXRmUitPUzdqMmFPQ2x2RFN4eHZpY3MwODBIZWwzRVZFVzZyM2lNK3p1TkxlMXNobkhTNFlMbGpRcWppTitNRUF5YUNUdEtMekxnTHdtaHNIUVUySzlaNGdVOU8xRVlQTFJoa0lUZ3g4bHVJamNnN2ljaVN6TE1ZblgxaEVXYWVUTFJzandFcHVuMFdmalRqRXZEbkJCK25aNGloeWlReEZCelRQaDlCY2FKNWhEaHFwV28wVjBZQUFKYzhvUmdnemtUYVBGM0tJYm56NGg4YmRkUlRMZ0xsUnhXU3BkNzh3ZWJaVUdaN1BQM05LMCtQVThZampsSzlnSzFtZVZKTVlVSC8wOGwvL0t1MnpYY0RZbU9HWDlZV293dk04a0RHSVBFM1Q1UTg5dUJrbEhsZW44d004ZUhkclNSdDBpdDhlWm5ObklKdTltUFo2eFZ6dTZSV0VaOGhOUWdqdk9TZHoxbWp6VVpsZkRkc1czdS9VaFVoR2FFZUdtSndlaDRudzkyZjZmVFdJcHo1WUp0UnNZYko3eTZUY2srb3NocmdjRVRjamJNK05tR0xrVTNCZld2cndxY1o5czZ2RUVmZWlOVlJlUT09In0=";

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