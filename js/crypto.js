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
const ct_serial = "eyJzYWx0IjoiQzdhaXFYcC9zZVF5alhCZVFWVWdLUT09IiwiaXYiOiJhZm9BeVpNaGNteXFSa0tXIiwiY2lwaGVyIjoiaGFQMkdVNmRueHYrL25rMUxLRXl5UXNkdkxGSkhqVlJhc1hFS1hMVmdkRktnc2xySU1uNVViWEZhMUdVTGRWejZaUUtmQXB6MjdmZFQ1aFVyQ0s5cWNCN01nRDZQOHV1RkVONWdDcHhMYkRnQmY5Q3U1WGFiZmhwVTdJTjZONWFyMXZEZUlKSktxSjNHbVhoZ241dGNIUStQSWVxb2ZabDcwVFZsbmFiREhRK21WVG4wUXlGMlFRTG5SaWJzS1FiSk5iZWRKUk1XUjFrbU9IVlJqZ2RyQVBiVE12U2xYWFBXMmNZRmJsNURUeE9UckFwR3dsOGdMUzdwWU5oeUVCS3RqYVJrME56Ymp0V1YzektRWnphWmwrMTIxNGdPczg4ZkV3cHRlTXhzbnlidG5sQWxVblFQdnE0bFZvMjBNcmZ3cUgwQ2x4bXdPTzdJQ0pJcVVZemVCZVFvNUJPRStLdFYrdGp3U2w2bDl4ejRxYmhjN091dG5WT21QdENzak8xSXNZVEdQZlpzRENQMURtVEZHR1N3OHZHa1FQdDZ3UVBlVW5xRmRFTjcyRmhTUGlKWEFCSS9iV2hVSGFnNkg0OVFXVHlDa2xNTXpQbnd5R1JWWFhnU21uSlREc0tOQjJPek9BeS80aWhtV0xwYVQ5amhSYUdienpIa3djS1RiWjJKZnljb0lVaVphYjB3MzJENlZZR2VhWUpyaU9yMzN3TlMrUDhOUWR4dDhqMzJDRGJDSmQzYzRPTERiN1VHZnY5bGhKb1pTQlV1NmlWbFp0UU9ZaVBZSFF0VjhaRnM2ZjV4WFpaRkgySWNKT3BTQ1pvSHRZMVpuNVVkY2dHbi9TenhROE5pYm9hdHU2MC9PeDNBVXAzSkVmTWtwOGNCcEZZK2NFdnRvMjlRNXdNWmkwTnU1Q1ZTMTF2eUVUTHhJVVJxRlM1YTE3M3pKN1k2bUZZM1dhZGlHS0taREttc05tNHROS29rVjBHNzVnV0FHWThSVU5iUzVXdW1MUVpuZ0xkdHB1VG1pWDZuQ1VvNzl3eXF4VkJDN1pwMm5pN21MS1k5UGp2NFU3Q1VCdGVQZ2pRSEZSdkgvUjVZaklqV0hEMEd5WXkzUXZIQlNOZWdubWJPRnNtMmpqQ1d0NVdqYjlCMmpDSGdFaVY2R282elZ5VGZDOGtYY2F1UWVoRVBJZ2NEbm1LVm43Zm1SbkNaV215ZGZhSWpwS015Zmt2UFJkUmdoQUpIOTFRR0F5c1oyZFBScXdwVlJneEhTbXB1bGhrQ2tKOGFYRm85Q0tLVUIyUHV5aVVEUnBiUU4xUGhLaW5MNCt4SGFCWlhRZS91SzFMdHViTkQvR01rbTF1TUNpTVdxMUhNaHZrRW1kbkYxbTcwWHJsU0R4VkhJWlBoaUFBSHc5SzlPbzM0eEJUY0VTYW9raW1MUHBwb1k1bTN4dHhNWm50dmFMZ0JlRHBwc2Y0b05wWjNhVi9HQVJYeFc5aWpadnJLMWdnOGhTbWorWFlCeDJKQ1F5d1Z5S21URTM4QmNwenp5WWRqNDBybDBRcnNyY0VzV2dQYndaU3lDMXdkdk5qMitpaUlLelRDelg2blFpWEV1aVBMK3VUYUlxYnZ4MVlhNnB4Y2NRNTFQWXBpNXFrVjZqcGlUdzkyeHpOT2JaQ21WUVVKUVkxZ25EVGJqaytJRFJxUHFTZU5jaEtMTS9UYzlENXl5K1UwSnN5VlMzL2N1djRRTmNuaGRPZ2FocTBWRmJIZW82a0xHZzY4QlVhSTR1WkpMVEQ4QjNMOXREVXhSc2l5a1BVVHJZSEl3SURoQm1TbkMrbVhqdGlGc09OVngrdGJ3amRzRWVtZ0s3Vkgrck1iUk9YRDAxRWNtM1N2N2xWNlFheWg2VXhUbFFWVGdXNGg1MkQvTjRHVU9CSndtYzc3eEgzUWlQRldQeFJIa29pQW9qbXNoZkdVa2p4NzRlU2h2aElHcmNnYmR3TUF5SnpKei9nZkxYak1sYXBxK0tWbFkvZlZBUnlkTGxTcDVTTTVZeFpYTHdtTWZnRWxjTG1GQWR3UFBJWjZxeVVMRjF0MGVESVJsS2VQU2ZhYm9rekxQKyt6R0FRSTZTbUNhNVI1UzdvKzhhTjYrcm5kY3FQbExDa2xIWi9wL2RuUGlUdXBSZkxoaGIzeHRIOTJuOTNQZklLWEorUkxPUHZLNU8zTUYvRk9tNE1Gd2dHYUhaV2ErQSs4RUt4ZTNtbGI1ck9ReGVZWG1QVm9HV1lrRmxlZTBKeUMrMmZ6QVlSYkhNSjd4dXZVNEttdXplczFLT2dCTzNaS0oxajhiS2pWSDdvb2hMZ3RxbU1YTmJraWphSUl3TFJoeHA2U2R3NUNWRW82WVIveGJpbDh5SzRsMjAwbnBqWUN2N0ZYUWRwU3lScGVEOFZJWFAvOU5nanRFZERieEdscnd1ekw3ejNCeC9YajQwa1g4SHJKVW16aHovL2NIdDhKZjlhU3IwVG1CZWpXN0tYaENJc1NaZ2JpM29kR0tXRWt6TWcyTnRJdXFpRkYzcjZmaGN5MUZhNzNJNEU2eDVWenY0Z2d1NXRFNzA2WXkzeWhPcFhKZVMwcWRDQ3NpOXcwZTA4NStLcVhic2lGSnlNaHgxMFZ6ekl2YlZTaWlDT1ByeUJqbTh0TExwd0hiUnYzaDQ1OGI5TFRST2o5TzBXV1lqUUw5cXhlKzdSUXNobGo5aCt1bmQ1S0xuVkNWZTl3NVljYnkxRmV3Ulh0STh4RW5Mam1aWi9tZEQrTk9ITmlvQkRxWE1Wci9rSGFNNnNRUVJRM2Z4M055UjNsSHgzYjdsN002WGZJWFpRQ2ZlcHRRcUlpU0EwTTE2bWlCWnZ4R2JKSkFjMVNoYVNHdlNWaFZjbVNHVkNIcFZQYmdmemRQUkg1RzBOMkhGbjJNbWw4bzNuV1hMZnhPQ2kzZWJwZFduc2VscFlaSE0vSnByMFdxL214RldtNDZpUXVMbVNkaE4yUDhkQSt2NXhKTmpKSk0wSmFkT2Nadmx3MVFUZC9LMXBRUitDSk5oV29QQzNtejhXenNBbmk5MFpRaWliLzVhTUxZTm9qcGNlNjJWcjVwY1NVMCtlZHVCZkdlSFMvV0x4WXVrZmtVRHcrUHRJZ0RLUnQ4T1U4cnp2Q1VDdHN1OTA5ei9lM3FBUk9EQTFoUzJWT2x4azNhcm0vVVhTYjZXaGRyWnBEYnNWbEpkYm5JTm5PcFBvUlFPTXRlQnB6aEJMYlVpNzhvdGdSaFlPcHB1U0NTckdnU1JkamY1QUVjOFZWNVRiQk1rWVhQVTU4Y2VxeWlPL200WWwzU2crVkk3ZVhhYW1uNWdUUkxUViJ9";

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