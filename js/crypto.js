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
const ct_serial = "eyJzYWx0IjoiRHVMdWxZSkk3WmoyRDVhWkRmbGhIQT09IiwiaXYiOiJLa3p6Y0F6K2ZZV2JRTk9HIiwiY2lwaGVyIjoiTUE3S1RsSlA2Y1FvaURFM0R3UE8yVnN4NS84am4rRUdLZmxkMThzd3FQRDRTL3EyTjlxM2RPYThmekQrZ3ZGY0EveUk5dndBczVrVUtlWlJSSHRXcmg1bmJRN1k3MEZlVUZPaGhhQkhlRkFPaDhYdmk0YkpodzZ4SGJmVC9LaFBDNEtJRkVzajg2QUEwdGtNbCtiSzI3N0Nwajgwc1daNFYvK0FiNzRjWFllUkRZUFdTeHhxT210TExES3FZT0twWnlJVEVlZGJZendBMDl1MGNJT1V2TXR5L0R2SkEza3NCbmkxUGNSR1Y3dlFLMzlJYkRSaXVqVU9JL1RudXhtQ2lnVjV4My9jeGtUL3ZZQjhNeEJjTU5BYzVGY1R2V3I0U3J6RDVUNDMvUTFWWTRjTi95dy9oZXJmZFp1Zy9OQXZndE5tT08wR2o2Wlk2bG5YcjgzbG5OV1AwM2pxMEN1Q0tGMExvSTV4YXBNQ0hyMEtzaVhtZUhlaGtNenVVUy9QcFB1YVBKc2EwR1hEVVd6MzFnbFNiNjRGbmIreE9BWjFQMmNEUUZDNndwUGpaVjZPMHA4YVBkSXJ6OVJpeU0yaTlsMWRaWXFlcG5DaTdVblNoODkyWUFyUGc1MDhDS3IyTDYwQlRiamF3M3NjVDU0VzV2YXRHajJZV2dJc2N6dlhGRjZnOVU2ZkhRUDdDcTV6YW5NeXhNc2EwekFpUFV4V05HbThUZVN0SzJvSzk4ckxkL1lYdWZyL3BlVUx2a2IwYjViSDQ1ZFJLWGhDRzRqckl2T1NNMU9xVVNtZHZpaDk3V3FheGpwYUJWMytjZHBnUGRxelFIaGdPR1FDUXcvRlpnejBpRmlUbDcvb2pUYzFjcUdjNDJIR0VQcGw1U0t5aUFFZVVXRTRuc0gvb3hILzM1eXMwSUdqWmlqVkhtQ0tUVWlTOHFLaGlVakRYMTM4MEI2NThlbzN4c0FWMDJObkN1bE5XOExEaEc4TEJ1cmcwWGMrUzRiaXJiakNPeERTR1RIaVp0dDFIaXBqVTFvaEtPYjlrSnY1S3FiNW94UDBaRmliVzk1czNKZWEwaGZnUURaTEs2Sm5xdjZXVGlJNTFyb0g2eUVnWW9RV2xGTVM4MG41d0s4Sjl3M3pQVGh4Z0RrN3gxOTRabnpGZ1B3cW1mdUljckpsYWhNblpzRkFmQlovUHl2eHFnd2llcWZONFZKY3FiRFVCS1BCUjQ2ZnB2cGRVVis4OCs4OXIxdGNaUStWaGI1QzF2Vkh0KzVBdXJHZHY0OTliVGxKaFhjaC9hZis1bUNpWlQraGNuRXVpSUlBbGNaZHhqaWUrSXpxamk2Syt2RFFab1ZGM3ZyR1cxSkZGVGFsK0lNeDFBMTltbkNCOGRhNFdmanhJbFVzdzAySmhzYlUweE9SeWphK3hqUGxGREI4K3JmdCt1Y1N6alRPV0hweFJMRWszcjVGVUFGbVVxUElEaVZIQjRPc2tnTExUa1F6aWttMng2ZzFqM0JzSC9rQ3hHRVZ2YnM3aTJGRVBNcDJ5czlwOGxEOXVTYU01SSt3bDl3K01xZ3RzTVMrc2RPT3ZvUU1IRkY1L2M4Q28rTmM1N1pGWlBpM0FObW1hanJpUHVTUEl3ZHVVa2M5Q1F6MGNNMTREZEIxL2t5bW4yTE9HMytvM1kxRVZlRUl0RmdXR09vZWw4dVk3dnhhUDM4ZmplVGZIMVdiQkhnc1g2UzdxNWs0VXMzTU5qa2NvcXBuT002T0tiVC94dFlUY0wzU3c3UVNPRE9mOXlodUo5Ykptd1p0VWlQeUI0ZUc0akExa3BYSWI2Tms3RCs3T2lua3YxYis3VjM2bExzODNZd2RCNzZpS3RPb0hvVFh2NVcyeEtYMUJybGpSM25XRGQ1NTQxOVRMbEhrYXQwTFZsY1pmQjR2M2lMcWFhNDYxa0pmSnBnQmNjV2hIUHJiVWVEdGxSSVlFSEZyNFcwSmx4Mmc1MFd2WURSZGQrNTNlMjNycks2YmRVanF6cy8zY1RYUU51V1R2N3NvUUxHYWoxSDR0SklMUC84aEtFR3Uxc0pZOHlnd2xUNys3M21xZS9wdlNNdm9JcksvRVhYY2tIR3NNRE92RXA5WmpmYmZMRVVPN3J6WnBKb3NGR0c2L0RDSHRMbXU3Y1VjQkRielJidFFTdFk0Zmk0RUttMnNQVXpCNUNYZjdvOUd0dUdPbXZCakV0QWtYU1pvSTF5OXp0VGF1NXdhVGlKTUlQVDk4N2tpMEhkQjAwQkpvTUFMcGg0TzRCTWl4UVNmU1JJNStqVEhaZDlGNStRSnlNWFRnTG5LWW5BbGIxeU14MzFyQXJ0eEhFU2pHekJvTXZUZUZzZFl5ZDNSN0o5a1NwSXNlVVZpc1RzUitjU2ZrQmxGeHJ2UTVpaTh0RUx2ZzRTcDM3VTAyL1NtWlpBNStlcXhDSDJqUXoyM1FUcGpscWk1T3ZaTGtCcmp1QmxodUU1NWhVVCtNbzB6U0dnblpPNjIycHpQakJlL2tyWTNPOXcyblptTk5YMk5maDdhbExUQW1aU05zRFRjZi8rbSt1aldsZVh5dGdNdVI2SVRzeU9sUHVGM2tLcGxiM1hxOUhLeDlsamhnWnV1Qjc4QU10NW9Xdk9CbjRhcGgzcng4NlRTcUlpOWE4T01ISFNVRm5lMHlPeGJBbktraThYMWhuVFRjbWNsdW43VTNVNWJ1ZG55QklkbTgxRTExVkg5R3ZhZWFpNnV4L2dzODh5dDdHVUk1SUxqbWI1TTQxVi84UHNpY0RvSHY5SzBtbGo1V0ZZQnoyTS9yVHhsREYzaHA0REVoTGpwWE85WkluU2dxV3pWeExCUVNKTDlNUE00c0s2amp1V1VZT2YvVVlLS2ZIeVhqNG5nVXAzSFF4ZU1DZXFaeXdqcWJFOHp0M29pN1AzSDlGT3ROQ0ppbnYwOVJNUEV3Um11T2cyd3htVXhTZHNUaHBacmlqUWNyNzVJMnl6QktwUUYxamhrUkhkeUZZcDF2c2c4WTVyN0Y0bUV2UjZOSXRqR0pKbEtsc011c1R4T0g0REE3MzA1Z2Q1VDBWZHY1bmQwcWRoVHJQTitRWnRsU3luV1ZVSkdpc0lwU3dIdERhVVptK2J5R2dxMzA4TitEZTdKQUhsT2FXYWIwUDFHSFMwRllqRGlNRmpDSk0rOW1yZzRUQjFoSTFrdVovZHJlQXpEWXJSM1hyRHNZK2E5TFpyWCtxa0JUNnczZWxVd1RlS3FYcWNHNnFDOURTSFQ2RWJaaU5KV0lNYkdPUUFpdFYzRTdRNUFKY21Hc1V0NThjcFhYWkxUci9QcjBhMi9mQ2ppTm5ZejI4V0YvZmZNS28vTzhlbXF4VUZLVk9GbWwwQW9Mck05cjRjbmd2c1RheHFvOERkbk1URm16ZGtvMC9YNGVrb0tzcEVRdHFRaktTZXhTdVFVZVZPR0tUc3NQTXNDSXpGd2tFclFoWUU9In0=";
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