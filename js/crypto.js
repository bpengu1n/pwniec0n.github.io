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
const ct_serial = "eyJzYWx0IjoibmU3MGdKR1Rlc0tlaVpobEI4LzVsdz09IiwiaXYiOiJUUkxFYnA1S05ucUhUV0VIIiwiY2lwaGVyIjoiUUVmUnQybWlZaGhPaVJtTU12SmRGSTJTby9JbkpIZWFpTVhINVV4MTROa0xuQTc4UFhtc1AxeUFLL1BONEVVTDA3TExWemU4dklCcmNtUmNEeFFVTC9xU1NhSjNRSVFpQVZwYjNsVWI1MlczMXZsNURVanJtamdKdDdZelRtcU5kd1RlUmtJK0xTdlNiVTBsdlRUUm9zNU1pUUlaQ29uYnJkYzFBTUFxY3lORHhmZWdnNGxyQjJEVGp6czhuZzd2ZHdBekx4SEswM3RWMk1ocDR0bkE4YVhlNFY3WFBVKzkvcGVOK2tBT0ZKcUwxSFE2ZW1tU21BYlQzU2xybnNmRkErcysrOUpadnlNOFVGOEY3SU5SZ3M0c0FCM3JXTDgzYWI3cW9hNWJoVHNoLytjRXMrMXhycS81eTYrWWVORW41VWNaZ3EwMFhObk5FYnNjTjR1cTZYcEx0YVZBUWZmTlQ5TXpDL0ZhWld3ZFhYK1RnQ0pGZnp3NWFMYm5mTVlpQ2Qzb1EyZ3NqbkRNSStISVJpNThnZjhZeU1mTEdCd2JvS1A0VXJDQVhmM2ZJU0FBWFNIbWs1eFloc2pkZUYvNkcvQkNHT3dGbXZMbUVoUmFVRXZ3NXNETFk5VzFOVjBuN25EVzJjSjhkVFlpTDloV2JZZGVlNDNuRjJOZGlSNGVEc3NxN1pVTXlYRnM4MjViQVNMWDBwQ09BcDlMYy9GMUdQendlSDVRdExGZzU1WDNFbFJQd2JIdkViSXZtT0ZRUS84YTFGZUg1bkdEbVNwclVycVVSbGJaZFhndmV2eStjQU9neUxjQ1NIL0k2b1FnWjdGUGFiT05Ic2JGNmRUNjI0c2cvakV1aFU5UEhRYlpCdUlMUWVhMmZXWUdSMU1zRXhjY3F4VUNlWkxxdUlLdEI2VEVIcjNvV2tWQ1V2YVh1UmxrMzVKTEZib3MrS2s5elFiVU4rUVpMejJUdXdyY2NZTnR1YjBEaUxBeGx2QW1iQVNGQjA0UVhwTlp6bDVTU1FzL0tOKzNBMGFHRFdRZFFNaHR4dXpKT3QvTGRLMkhNbEkySnpheWs5OTlsOHNheVJFQ24rdXdueURHS1VvczB5WFRWeFE1bmorN0dLYjNqNzI4YmFQTlowVGJSbHpSUng4d05tRG5hWnNJUS9JbC9hRTk2ZkNJaFhwV1pOUEZycFZ6Z1lqMjB1djNlRmQ5MDBrMTVSZlZiZDNUY05BTldkakowcElmR0pYeldqTFYrWk5veEFQQ0NmZk9PZXcrVVN5U2NDbUZVZkxDOVI5Y3B3aE0xK1MwcjlaY1dpYnF0VDJhK3hYWjk2aU9jRUgyMC9IVUY2amZ4NHJLN3REOVZqOUdFenVMcDNJYXcvMHhGdWhpWFlLK0RLU1pybU1JSGRsOE5ISE55bDIxTXBOdU96R1EwMDl4cmJYeEUxc2Q1aGIzZkxYWTAvaWxudER0enNjNFZEZTgzN1dSVmFRSmxJRWtXcjI0aUFUM1lXZzk0K2tSdmR3ZGpxSWd5NG55dEdCVWpwTm1idnVEb3Q5RWV6MjVVeEJkNXFONmJiTU4xTm1nZWxMZzcxcmlyVkxETWlORTdVeWxFUHYzT1RnQm1HWHQweXJjL0tPN0xMVW54MWZUTnAxTE91WVQyRkR4cGs0cUFIUzhiWTdSVjZrNnV2V0JPbFkyWjczaHBINUl5RWU1VFhteFZ2dS9RV0phdTUrRXNQTDlUbnZwT0tvUExiWWdOWU1WUm9jdW11NzAxd3RGckNreWYyOGo3ZFY2R2FtWnkvRUpySVlueExWUnkwTWIxVkdXblF2b2h2dUVOTzVVd3ZldkUwaXUyUTQ0TlJnT1Z0YVBMelNSdjR3UFZCd29HVmlKOGxPRC9xeW1KRGZNb2VkV3dXSlcwZmk1VkFsUlhxSWlWTEpvdTNvSnY3S3VaYzNGc3RENEoycU8vaTlDUkRNT0I0aEJzRngvbG12TzV5SWI5cTRNRGRPSDh2NkVicVpqRS9iRXB6RXlsdWhZRHhucGpoc2hZU3RrT0FGaGlzOUFyelRZd2tGZGRVdWJYQzdxSm5qUmV3VkQyMklPUUlyRHpXaFlUcUlQSWVGRDNJdjVRS3JnbjJ3Ny9hWWluUGQ5cm9OVkd0OTRRWUtmOVpHZG1nZG94cjd0NGRKNTh6NmpidS9tSlA1QkcxdnhoRTFsZGNlOSsra1J6SnNKRWFYbGVtOGk0Z29RaWYzbU9UcUFtRHh1UUdYeFQwWW5UY1lUM3BKZFdpeklFbEdCR29lbUoyRFBZeW9yZ2ZBczFjWXRteVc4K3ovS1pVT0VYVWx3emtheDJ6amRJSXlxQkpKMHJnOUF4L1l6RHRWd2ZvcW1RVU9qUWtaa0ZCUFMwVEUyNk44WlZacXIrME5mY2hlaGFqWmgybkNxUTRpSUFLM3dzK1AzMFNENGFFRXI1UlRjclY5REU3TExiYUg3WlNNRkJYU2VQR2duRHpFQkZmejZURWNSVkVNRkRpV2hxd1VtaHNsbEdISkVqYmFGNkJESVRjOTBNdFhzaVR0Wk1mTTFZNXpDcE1hd1htV1JyaTZCOXRZbkhCLzVrNHpuMnZlQ2J0am1aMGw2U0RUMlppSnlKYXZEQ0JwM2hhZUdkQjFZbTBlNUY5ZDBJNk1JU3g1ZEhxR3JDR1lWcytKanFLek84bjVNRUFjZzdjTUR1bElTT3ozeWIwRWNRR1BIZ0NSOVBYcGRSd2h2bFNyS3FvUEZlTTJJbHd3VFROM1ZCeXJjQS9HcEM4TytLNHdxRlV3S3FCK1VTVmNhTnc5Tlk1ckJreFRzTE56ckQ2dkpmSU5wK1RwdjViYkZBNnNtdUtPYzhBY0hBaVMxSzZiMTNSQTg3aXRsQ0w2MHRPNWhCWGxoNElYc2VEQllmNHpMR1NlZ1Y0WUVobndtYUo3cTdQYWZJTmNvNEExV051SlZQTTE5b1NKOHRHSlcyUDN1Q1Z6U2w4OEJVVlU5RkJLTVhiZDkvU1BOK3pWNklxdEpvVnJzcVEwdndGd2haTGgxUWxjTEFyL05aNVA5Sld5V3BrRHo4cU1pZS9QMjFHcG51T0dLMHZVM0xzL0tOb2hRMmFyUVdXQ04xbmRybHNtN0JDN1o4ekwvdUsxaUQweFNIZVpvVEhnRUliT3FSbGhsMDl0QkJoMTlEU0pYOEVZbGtoTnFwTkh0TW9MVnhTNkhvNkExSkQ4di9BUWczY2RrcFdxb0pCMlZvZWo1MUhUOWhRUjY4WDRrZEFZR2NpdTA2d1JpSFY1Q2NsdkZqWDYwaXROd1VCc3hPMldsYm1vVUhIVW1hT01KeXU2Z0kza1VQMlB0cnBCZktQK3d0ZGdzbGFMVlZadkpoZGp3TGtoWlRSNDhodFAvNi9LSEdHUnpZZFZTWGVlcjJsRnYwbVAxWmwxMkVENFdwVlhIancxcUFjYStVZlhDR1YyU0pTalpZcFkvOXZKVkFuV0V1Vi9ia1ZaeFpKK2xYTHFvdndJNHNFbklmcHRkdy9nUWtoZTlIOHZPNXpxY1RNbVRSVllYZ0FPOVB0WjNCazd6cDZmek0zeUhwekJHY2daS1dTcXpkeFR2R3lETFBSYTNJbTBjMSszZDZYc1RYN2phcjVGU2RKN1JHcUFOcEN6MkJzcWV4VkJHa2IxdUJOS0lHVm1hZDBpbk8xN3YzcWNOSUo4RlJxTW10enNPRCsxMEZMMG40MVN2YUVpQWRsNTdrNzNJVHVLckVkTkpHZkcyMXlvQkQ3UjdMKzF6NEpxRVJEeVVIR08yaFpJUHhRLzNwMXc5cUJKb3Q1L1Y0dmg3dnVUTkluRktzNGhwdDJacTVOK2NVUERJZVh6aWtiOVlRWE1Ha2RQTWFhQUd0S2VkSWtEQWVZOHRRbjJiMzNDaWR4TW1CZlROL2NiS09IR3FCMWJvWDhwa0FUOFl2UzNnbjBYemcxMlV2WFNPdVVvc1h5OEc1aHlOeXR1UzdFVEZxcm9Nd2xaNmxzUGVzUHlLbmRjd0xlNXZBaS9VV2ZUUkhpQ2oxMlRlamdPYmsya2dlSDRJSFdubkt5aHBJc1dXQ2VHWDVWYSs2cHFROG9nNU9IaXVmaHRkMUVyL21FWnBheHNseC9NWDhqTXJBcUZlOTViVm5OSUpNYlU9In0=";
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