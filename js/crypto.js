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
const ct_serial = "eyJzYWx0IjoiSm5vSk5DZ2pBL0JOL1dKbk1RWTFwZz09IiwiaXYiOiJUTjBYZTNmLzUrWkZGUlR5IiwiY2lwaGVyIjoiN3lVdWY5WENucTBoRC94dE05T3AwN2tKbStkT0tpRWxxR1hZb2ludWlmc3VDUk9FTDRsWm52NDh6VW1wS0xia0lyYU8wVHZpN3g2ejZULzVnWVZzclVIdFZRbWg0a0dsdDVDcHErbnZPRTRqRGxzeEZuenVXcy9oWWFPcmdlSVM1NG5IU3Ridi93Z0l1K3Z3THd5a1dQZ2xla0RDeWQzZk5TS01HZ1VvZzFhZDVJajFpQkdzQkJJMVZEWVRia25Lek9rMVZSaFVyL2tvZEhianA1R3F5YkczK0k0UGtLQUhHS1c1NU1ITGl3b1NVbCt6UExKeFE5ckpHNTdTSWxKaUFJZlNVcndVN1JRWkJiMkxndndDSFdOcjBQT2J5S1JJQ1NuY1lkLzdaYlc3MnBJeGNZcFRkL0thdVh6TlNDbFBiTFNuOGtwYk5ZclB6V0lLK3ZEOUZtTWJHbmRmcTlnaHRNdHVzK3V4UVhPQTNTRklHcVRLc2VKN054ZUZHNGZRaUt0YzFDa0pTTThvY0Q3YzdIMkRQM1pMYlpIMmdyK0RGamZ2YjFlckVPYkxNK2dsV3l3S1JCM1N4RDNNYVgxeVJ6NnhPV0k4SHFaUDNFUWdZQ3RKZlVJdVpsOWlPanhRYzU1RzdzNmJRNjMvQWEwMWI0ZTdJcmI4NlZkNENnY2tNT28vaXh1bWtUSk5ycS80Q2Z1bnp6QTRHNEZJeGJHVFN5UzIvSllDQnZmODN3bzUzWTl5RHJLMmVPcjl5YU1BVldUWml1cVhEamwzeHVpTnpOckFmeVpOZlZQWlZHemovRlNITlJoMUxiVVBrMjJZcDRuM0VtU1puaGFMWStIcE9xZXRZcXU4R1ZaTVQ0TjcrYTZGRlVoR1RoZzJXaTJ2YjBYWEdUVGdVZmJEYVRtak0rVEVvRUtUUjFhTm14VGM0UTVWcGpTVzBvWVdIWEVIUFNUeWdjTFFkVXBRa1d0TDRnVzRpYjduQ2NVcUE5dUZwdkE4Wkt3RC9VSnFmcDJBQVUvcWV3OXdndWdUSnRrb08yTTJkeE9WYjRQdHdid0EvZm5EYnBUb3h4U0ZvUnYvUGxPMHo3RmV4NHg0a051cU9oWDMxVXRHNHY4d1FaNmhlalpaeXduTlF4V3dNeWd0R3MrWE5xcGI0WENLMHVqVCtnank5STlJYUdFeU5pcU9ILzl5aTN1Vk93c0NaQW0wK3EwdU1DSG5YSVAwbGFUVkZlQ0Q2b2J5VzVSNXlzZDRzM0xIOTNxVVlaK2tHUmo2bVBRd0tiK2FGWktTL3lRQWQxdFZ3NUFyOUUxQUR5bkR2WkRYTzVLeTc5Yi9aVjlKeXVHSDN6WGsvK2JOQTk3ak44SzhEYmExZjU0empVWkxSZFB4ZEI4ekdCMFpuczZiY0xBZVVGdWFldUJEL3drNWtUZ2xESVVoSTRvTURHcXdyaGorWlJwL0tZNG5KbUtmRXl1WWtES1dUck05VFlyYlZ3VmlqY0puOE85UTM4eEthK0J4NmdPc2lzQnVzcjc3NXFmVjRVY0E5K0E0WnlXZHcrVFFiRG5Cak9RZDJtendnRFgrb0ViTjltNjBJdEx3K2IvbENiUEh6a3dLNTVkKytHSXp1YS9QMm13ODh3cVVMZ2pURTN3alB2VzJpeThSSEdocUJ0cHJBZytPbmNwQ3R4ZVBKUzFDYS85ZEdESld1VlhGQXBEWER4Z2ZCaXFUeVdiWFNTSmVMdzQ1Qyt3cnAyVUxPTnB4blFQdFpOTnZsY0pDUE12S3FIVWk4RFZLa2U2N3d4blNucHlwRUNUNEtFSk5TNzd4QVI2NjJuenpiYW5wTmdxbSsrUW9PWWw0OGN5ZWM2cGxYSlJoQkRqbDh5UkpaaUxBbnRYcDB4cjRZMENneHNscWNmS3pYVDB4MTVNS2JQSUpLWHhicDl5UnBrbHRINW9tbUVwOVF3ald0WmVwbmlKUmw1R3AzbENONVhBRzNHVUJ0Z08rNmMyUW5hSXRSbmllU2d2Q2xzZlpNRS9ZaHAxWFMvdWcyV1M1dW9vYm5OUUl0eENDSW55TXhwV1ZPTDc4U2xLSHpBSDc0R2pTS3dmUjBRVzZLSDNhd20wUlpNY3d5cHRXTmhrTkNPNm5DdVQ2ckJTQk9iR1dzNHFNcFpJVk9VTllOYzdMamxHT3VyYnkrczRNLzN2U0llQUY5aFFlWmZYakROc21KSTd0M0VhQnBZUWdRT0hkM09OcWl3cTg4dDhVM0JTeGpWVUVRbmRlQzQ3WUR1ZlFzWkJJSTczWU82SzNGSzVPay9JSmtLTG9ERnZPZ24wSCtzZWRHQUlqYll4OFp5UXMrK1FvTUx0bmZscng0TzlIYS9OSDJGOG1ubEJ1TFZGdEZqL3d3bVo5b0tpSVRlQjJFR3N2Qko5NjNDc1JvaXpoc0pWL2lKNFNHb21QUGswTGNrbG1zd2o4bFhYK1k3NDJhblpydEMrMmVHdklMb0VrTGhjSkRuMHNKQWl3TE85TGJ1UlFockdCdUpleUprUGphRjM2c1l3QU9VTkdwSERRTzBIcFZuRXVoTkZ4bG1Yald1WFk4cW5VZ2RWeW00RkppUUU4NGlPNmw0VjJuN1lwVEhoL3VXOXdhYzJjZGhmbjJRL25vUVliM2V1VWZjRGZ0RnlXdVdNdDVqYWNOVVorOEdNSFV5RkpyY3JwOGtLK0ttK2lSeFhnQ05kUllsWWlzV3pWampnRW9GNzJXV0htbDVJME50S050WkRkS0lMNDM2RHFhNFlGaXkwZDBZU0ZwQWdBKzJaeTJraFJwTExFclN1S0YwNXF3ZWYvOGtvZ1h5aG03WTF3bnZsZnJxWnVFZklnZFhtRDdDbmNzcmhwc0RHMHluRDk2VWRXM3NleEZ6VDB5ZDhkZ1JGMWpwRmRaelY1WlBHVDZTNGUxeXRnREljemF1eUJ3MUVTUkwzNkRNWS84Z2tiV0R0dmViN0wzRU1UQVFuOEJNZlI0TlhYdDFlOTZFODU4eUF1NHFWb2c5WnpuZlF6YnRYS0xWSjdNcTBaMm91bkIwV1JpMDhlRllmeFZJY002K0VSckNWU2IycEQrMFB0OWIzdm05OTRYaWd1Z29jWjJWdjkrSzRaRDBXSXJmZnpQUjhXT1JVK1p5elNSKzJZdVN0Wm5QLzd4V1hMTE80Uzh3cFNaSm9IVSt2STdhNDhaM3V6YUx2N0RPZUY1VEpRdUZFektxTG8xeXdLaTFjcHdIazVxNFZ5SFlwSG9MRDkvTENIekl1bkFUTDhjT0g2c092dWRPOVQzeWJSdTJOYllRYko1ejFEa2JNcVpjckUvUFZ3Mnc1RlEyS3o0TTJFeWlmd3dwSzlnd282bWloMkVTSGhib2wwVU1xekFBd1dUVUtzZmdGUVVueHJmcGFva0ZYWjVVelBIYlBRL2hyS3UwMTRWR1M3MmRCbzBtRVQyUTQ9In0=";

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