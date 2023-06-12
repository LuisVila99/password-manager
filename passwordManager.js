const readline = require('readline');
const crypto = require('crypto');
const fs = require('fs');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const PASSWORDS_FILE = 'passwords.json';
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const ITERATIONS = 10000;

let masterPassword = '';

function generateSalt() {
  return crypto.randomBytes(SALT_LENGTH);
}

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, 'sha512');
}

function generateIV() {
  return crypto.randomBytes(16); // 16 bytes for AES-256-CBC
}

function encrypt(text, password, iv) {
  const cipher = crypto.createCipheriv('aes-256-cbc', password, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decrypt(encryptedText, password, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', password, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function savePasswords(passwords, salt, iv) {
  const key = deriveKey(masterPassword, salt);
  const encryptedPasswords = encrypt(JSON.stringify(passwords), key, iv);
  fs.writeFileSync(PASSWORDS_FILE, JSON.stringify({ salt: salt.toString('hex'), iv: iv.toString('hex'), passwords: encryptedPasswords }));
}

function loadPasswords() {
  if (fs.existsSync(PASSWORDS_FILE)) {
    const data = JSON.parse(fs.readFileSync(PASSWORDS_FILE, 'utf8'));
    const salt = Buffer.from(data.salt, 'hex');
    const iv = Buffer.from(data.iv, 'hex');
    const key = deriveKey(masterPassword, salt);
    const encryptedPasswords = data.passwords;
    return JSON.parse(decrypt(encryptedPasswords, key, iv));
  }
  return [];
}

function getPasswords() {
  return loadPasswords();
}

function saveAndExit(passwords, salt, iv) {
  savePasswords(passwords, salt, iv);
  console.log('Passwords saved. Exiting...');
  process.exit(0);
}

function promptMasterPassword() {
  return new Promise((resolve) => {
    rl.question('Enter Master Password: ', (password) => {
      masterPassword = password;
      resolve();
    });
  });
}

async function startApp() {
  console.log('Welcome to the Password Manager CLI');
  await promptMasterPassword();

  let passwords = getPasswords();
  const salt = generateSalt();
  const iv = generateIV();

  rl.on('line', (input) => {
    const [command, ...args] = input.trim().split(' ');

    switch (command) {
      case 'add':
        if (args.length !== 2) {
          console.log('Invalid arguments. Usage: add <service> <password>');
          break;
        }
        const [service, password] = args;
        passwords.push({ service, password });
        console.log(`Added password for ${service}`);
        break;

      case 'get':
        if (args.length !== 1) {
          console.log('Invalid arguments. Usage: get <service>');
          break;
        }
        const [serviceName] = args;
        const foundPassword = passwords.find((p) => p.service === serviceName);
        if (foundPassword) {
          console.log(`Password for ${serviceName}: ${foundPassword.password}`);
        } else {
          console.log(`No password found for ${serviceName}`);
        }
        break;

      case 'list':
        console.log('Stored passwords:');
        passwords.forEach((p) => console.log(`${p.service}: ${p.password}`));
        break;

      case 'quit':
        saveAndExit(passwords, salt, iv);
        break;

      default:
        console.log('Invalid command');
        break;
    }
  });
}

startApp();
