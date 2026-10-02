'use strict';

const DB_NAME = 'secure-file-sharing';
const DB_VERSION = 1;
const KEY_STORE = 'identity';
const ID_KEY = 'client-id';
const DISPLAY_NAME_KEY = 'display-name';
const KEY_PAIRS_KEY = 'key-pairs';

const AES_KEY_BYTES = 32;
const AES_NONCE_BYTES = 12;
const AES_TAG_BYTES = 16;
const RSA_PSS_SALT_BYTES = 32;
const MAX_FILE_SIZE = 25 * 1024 * 1024;

let identity = null;
let selectedPeer = null;
let selectedPeerData = null;
let pollTimer = null;

function $(id) {
  return document.getElementById(id);
}

function setStatus(message, state = '') {
  const status = $('connection-status');
  if (!status) return;
  status.textContent = message;
  status.dataset.state = state;
}

function setFileStatus(message, state = '') {
  const box = $('file-status');
  if (!box) return;
  box.hidden = !message;
  box.textContent = message;
  box.dataset.state = state;
}

function appendLog(message, type = 'system') {
  const log = $('message-log');
  if (!log) return;

  const item = document.createElement('li');
  item.className = `log-entry ${type}`;
  item.textContent = message;
  log.prepend(item);
}

function logCrypto(message, data = undefined) {
  if (data === undefined) {
    console.info(`[SFS] ${message}`);
  } else {
    console.info(`[SFS] ${message}`, data);
  }
}

function openKeyDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(KEY_STORE)) {
        request.result.createObjectStore(KEY_STORE);
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function keyStoreGet(key) {
  const db = await openKeyDatabase();

  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, 'readonly');
    const request = tx.objectStore(KEY_STORE).get(key);

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function keyStorePut(key, value) {
  const db = await openKeyDatabase();

  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, 'readwrite');

    tx.objectStore(KEY_STORE).put(value, key);

    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function makeClientId() {
  return crypto.randomUUID();
}

async function generateRsaPair(name, usages) {
  return crypto.subtle.generateKey(
    {
      name,
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    false,
    usages
  );
}

async function createIdentity() {
  const storedId = await keyStoreGet(ID_KEY);
  const storedPairs = await keyStoreGet(KEY_PAIRS_KEY);

  if (
    storedId &&
    storedPairs?.signing &&
    storedPairs?.encryption
  ) {
    return {
      clientId: storedId,
      keyPairs: storedPairs,
    };
  }

  const keyPairs = {
    signing: await generateRsaPair(
      'RSA-PSS',
      ['sign', 'verify']
    ),

    encryption: await generateRsaPair(
      'RSA-OAEP',
      ['encrypt', 'decrypt']
    ),
  };

  const clientId = makeClientId();

  await keyStorePut(
    ID_KEY,
    clientId
  );

  await keyStorePut(
    KEY_PAIRS_KEY,
    keyPairs
  );

  return {
    clientId,
    keyPairs,
  };
}

async function exportPublicKey(publicKey) {
  return crypto.subtle.exportKey(
    'jwk',
    publicKey
  );
}

async function apiJson(url, options = {}) {
  const response = await fetch(
    url,
    options
  );

  let data = {};

  try {
    data = await response.json();
  } catch (_) {}

  if (!response.ok) {
    throw new Error(
      data.error ||
      `Request failed (${response.status})`
    );
  }

  return data;
}

function bytesToBase64(bytes) {
  const array =
    bytes instanceof Uint8Array
      ? bytes
      : new Uint8Array(bytes);

  const chunkSize = 0x8000;

  let binary = '';

  for (
    let i = 0;
    i < array.length;
    i += chunkSize
  ) {
    binary += String.fromCharCode(
      ...array.subarray(
        i,
        i + chunkSize
      )
    );
  }

  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);

  const bytes =
    new Uint8Array(binary.length);

  const chunkSize = 0x8000;

  for (
    let i = 0;
    i < binary.length;
    i += chunkSize
  ) {
    const end =
      Math.min(
        i + chunkSize,
        binary.length
      );

    for (
      let j = i;
      j < end;
      j += 1
    ) {
      bytes[j] =
        binary.charCodeAt(j);
    }
  }

  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(
    bytes,
    (byte) =>
      byte
        .toString(16)
        .padStart(2, '0')
  ).join('');
}

async function sha256(bytes) {
  return new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      bytes
    )
  );
}

async function importRsaPublicKey(
  jwk,
  algorithm,
  usages
) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: algorithm,
      hash: 'SHA-256',
    },
    false,
    usages
  );
}

async function getPeerPublicKeys(peer) {
  if (
    !peer?.public_keys?.signing ||
    !peer?.public_keys?.encryption
  ) {
    throw new Error(
      'Selected peer does not have complete public keys.'
    );
  }

  return {
    signing:
      await importRsaPublicKey(
        peer.public_keys.signing,
        'RSA-PSS',
        ['verify']
      ),

    encryption:
      await importRsaPublicKey(
        peer.public_keys.encryption,
        'RSA-OAEP',
        ['encrypt']
      ),
  };
}

async function getDisplayName() {
  return (
    (await keyStoreGet(
      DISPLAY_NAME_KEY
    )) || ''
  );
}

async function register(displayName = null) {
  identity =
    await createIdentity();

  const savedName =
    await getDisplayName();

  const name =
    (
      displayName ??
      savedName
    ).trim();

  const publicKeys = {
    signing:
      await exportPublicKey(
        identity.keyPairs
          .signing.publicKey
      ),

    encryption:
      await exportPublicKey(
        identity.keyPairs
          .encryption.publicKey
      ),
  };

  const data = await apiJson(
    '/api/register',
    {
      method: 'POST',

      headers: {
        'Content-Type':
          'application/json',
      },

      body: JSON.stringify({
        client_id:
          identity.clientId,

        display_name:
          name,

        public_keys:
          publicKeys,
      }),
    }
  );

  $('client-id').textContent =
    identity.clientId;

  $('display-name').value =
    name;

  renderPeers(
    data.peers || []
  );

  setStatus(
    'CONNECTED · IDENTITY REGISTERED',
    'ready'
  );
}

async function saveDisplayName() {
  const input =
    $('display-name');

  const name =
    input?.value.trim() || '';

  if (!name) {
    setNameStatus(
      'Enter a display name first.',
      'error'
    );

    input?.focus();

    return;
  }

  if (name.length > 32) {
    setNameStatus(
      'Display name must be 32 characters or fewer.',
      'error'
    );

    return;
  }

  const button =
    $('save-name');

  if (button) {
    button.disabled = true;
  }

  try {
    await keyStorePut(
      DISPLAY_NAME_KEY,
      name
    );

    await register(name);

    setNameStatus(
      `Name saved as “${name}”.`,
      'ready'
    );
  } catch (error) {
    setNameStatus(
      error.message ||
        'Could not save the display name.',
      'error'
    );
  } finally {
    if (button) {
      button.disabled = false;
    }
  }
}

function setNameStatus(
  message,
  state = ''
) {
  const box =
    $('name-status');

  if (!box) return;

  box.hidden = !message;

  box.textContent =
    message;

  box.dataset.state =
    state;
}

function renderPeers(peers) {
  const list =
    $('peer-list');

  const empty =
    $('peer-empty');

  if (!list || !empty) {
    return;
  }

  list
    .querySelectorAll('.peer')
    .forEach((node) =>
      node.remove()
    );

  empty.hidden =
    peers.length !== 0;

  if (
    selectedPeer &&
    !peers.some(
      (peer) =>
        peer.client_id ===
        selectedPeer
    )
  ) {
    selectedPeer = null;
    selectedPeerData = null;
  }

  peers.forEach((peer) => {
    const item =
      document.createElement(
        'li'
      );

    item.className =
      'key-item peer';

    const button =
      document.createElement(
        'button'
      );

    button.type = 'button';

    button.className =
      'peer-button';

    button.dataset.peerId =
      peer.client_id;

    button.classList.toggle(
      'selected',
      peer.client_id ===
        selectedPeer
    );

    const dot =
      document.createElement(
        'span'
      );

    dot.className =
      'peer-dot';

    const identityText =
      document.createElement(
        'span'
      );

    const strong =
      document.createElement(
        'strong'
      );

    strong.textContent =
      peer.display_name ||
      'Unnamed browser';

    const small =
      document.createElement(
        'small'
      );

    small.textContent =
      `Client ID · ${peer.client_id.slice(
        0,
        8
      )}…`;

    identityText.append(
      strong,
      small
    );

    button.append(
      dot,
      identityText
    );

    item.appendChild(
      button
    );

    list.appendChild(
      item
    );
  });

  list
    .querySelectorAll(
      '.peer-button'
    )
    .forEach((button) => {
      button.addEventListener(
        'click',
        () => {
          const peer =
            peers.find(
              (item) =>
                item.client_id ===
                button.dataset
                  .peerId
            );

          selectPeer(peer);
        }
      );
    });

  updateActionButtons();
}

async function refreshPeers() {
  if (!identity) return;

  try {
    const data =
      await apiJson(
        `/api/peers?client_id=${encodeURIComponent(
          identity.clientId
        )}`
      );

    renderPeers(
      data.peers || []
    );
  } catch (error) {
    setStatus(
      error.message ||
        'Could not refresh peers',
      'error'
    );
  }
}

function selectPeer(peer) {
  selectedPeer =
    peer?.client_id || null;

  selectedPeerData =
    peer || null;

  document
    .querySelectorAll(
      '.peer-button'
    )
    .forEach((button) => {
      button.classList.toggle(
        'selected',
        button.dataset.peerId ===
          selectedPeer
      );
    });

  const target =
    $('selected-peer');

  if (target) {
    target.textContent =
      selectedPeerData
        ?.display_name ||
      'None';
  }

  updateActionButtons();
}

function updateActionButtons() {
  const enabled =
    Boolean(
      identity &&
      selectedPeer &&
      selectedPeerData
    );

  if ($('send-test')) {
    $('send-test').disabled =
      !enabled;
  }

  if ($('send-file')) {
    $('send-file').disabled =
      !enabled;
  }
}

async function sendTestMessage() {
  if (
    !identity ||
    !selectedPeer
  ) {
    setStatus(
      'Select a peer first',
      'error'
    );

    return;
  }

  const input =
    $('test-message');

  const message =
    input.value.trim();

  if (!message) {
    setStatus(
      'Enter a test message first',
      'error'
    );

    return;
  }

  try {
    await apiJson(
      '/api/messages',
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/json',
        },

        body: JSON.stringify({
          sender_id:
            identity.clientId,

          recipient_id:
            selectedPeer,

          message,
        }),
      }
    );

    input.value = '';

    appendLog(
      `Sent to ${
        selectedPeerData
          ?.display_name ||
        'peer'
      }: ${message}`,
      'outgoing'
    );

    setStatus(
      'TEST MESSAGE RELAYED',
      'ready'
    );
  } catch (error) {
    setStatus(
      error.message ||
        'Message could not be sent',
      'error'
    );
  }
}

async function buildSecurePackage(file) {
  logCrypto(
    `SEND · ${file.name}`
  );

  logCrypto(
    '[1/6] Input file',
    {
      name: file.name,
      size: file.size,
    }
  );

  if (
    file.size >
    MAX_FILE_SIZE
  ) {
    throw new Error(
      `File is too large. Maximum size is ${formatBytes(
        MAX_FILE_SIZE
      )}.`
    );
  }

  const plaintext =
    new Uint8Array(
      await file.arrayBuffer()
    );

  // AES-256-GCM file encryption.
  const aesKey =
    await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      [
        'encrypt',
        'decrypt',
      ]
    );

  const nonce =
    crypto.getRandomValues(
      new Uint8Array(
        AES_NONCE_BYTES
      )
    );

  const encryptedWithTag =
    new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          tagLength: 128,
        },
        aesKey,
        plaintext
      )
    );

  const ciphertext =
    encryptedWithTag.slice(
      0,
      -AES_TAG_BYTES
    );

  const tag =
    encryptedWithTag.slice(
      -AES_TAG_BYTES
    );

  logCrypto(
    '[2/6] AES-256-GCM complete',
    {
      nonce_bytes:
        nonce.length,

      ciphertext_bytes:
        ciphertext.length,

      tag_bytes:
        tag.length,
    }
  );

  // SHA-256 is calculated over the original plaintext,
  // matching the project design.
  const digest =
    await sha256(
      plaintext
    );

  const digestHex =
    bytesToHex(digest);

  logCrypto(
    '[3/6] SHA-256',
    {
      digest:
        digestHex,
    }
  );

  // Sign the SHA-256 digest with
  // the sender's RSA-PSS private key.
  const signature =
    new Uint8Array(
      await crypto.subtle.sign(
        {
          name: 'RSA-PSS',
          saltLength:
            RSA_PSS_SALT_BYTES,
        },

        identity
          .keyPairs
          .signing
          .privateKey,

        digest
      )
    );

  logCrypto(
    '[4/6] RSA-PSS-SHA256 signature generated',
    {
      bytes:
        signature.length,
    }
  );

  // Wrap only the AES key with
  // the recipient's RSA-OAEP public key.
  const recipientKeys =
    await getPeerPublicKeys(
      selectedPeerData
    );

  const rawAesKey =
    new Uint8Array(
      await crypto.subtle.exportKey(
        'raw',
        aesKey
      )
    );

  const encryptedAesKey =
    new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP',
        },

        recipientKeys.encryption,

        rawAesKey
      )
    );

  logCrypto(
    '[5/6] RSA-OAEP-SHA256 AES-key wrapping complete',
    {
      encrypted_key_bytes:
        encryptedAesKey.length,

      recipient:
        selectedPeer,
    }
  );

  const packageData = {
    format:
      'sfs-package-v2',

    file_name:
      file.name,

    file_size:
      file.size,

    sender_id:
      identity.clientId,

    recipient_id:
      selectedPeer,

    file_encryption:
      'AES-256-GCM',

    key_encryption:
      'RSA-OAEP-SHA256',

    hash_algorithm:
      'SHA-256',

    signature_algorithm:
      'RSA-PSS-SHA256',

    ciphertext:
      bytesToBase64(
        ciphertext
      ),

    nonce:
      bytesToBase64(
        nonce
      ),

    tag:
      bytesToBase64(
        tag
      ),

    encrypted_aes_key:
      bytesToBase64(
        encryptedAesKey
      ),

    sha256:
      digestHex,

    signature:
      bytesToBase64(
        signature
      ),

    ciphertext_size:
      ciphertext.length,

    nonce_size:
      nonce.length,

    tag_size:
      tag.length,

    encrypted_aes_key_size:
      encryptedAesKey.length,

    signature_size:
      signature.length,
  };

  logCrypto(
    '[6/6] Secure package ready',
    {
      format:
        packageData.format,

      package_fields:
        Object.keys(
          packageData
        ),
    }
  );

  return packageData;
}

async function sendFile() {
  if (
    !identity ||
    !selectedPeer ||
    !selectedPeerData
  ) {
    setStatus(
      'Select a peer first',
      'error'
    );

    return;
  }

  const input =
    $('file-input');

  const file =
    input.files?.[0];

  if (!file) {
    setFileStatus(
      'Select a file first.',
      'error'
    );

    return;
  }

  const button =
    $('send-file');

  button.disabled =
    true;

  setFileStatus(
    `Encrypting ${file.name}…`,
    'ready'
  );

  try {
    const securePackage =
      await buildSecurePackage(
        file
      );

    const packageJson =
      JSON.stringify(
        securePackage
      );

    setFileStatus(
      `Sending encrypted package · ${formatBytes(
        packageJson.length
      )}`,
      'ready'
    );

    const data =
      await apiJson(
        '/api/transfers',
        {
          method: 'POST',

          headers: {
            'Content-Type':
              'application/json',
          },

          body:
            packageJson,
        }
      );

    setFileStatus(
      `Encrypted package sent: ${data.filename}`,
      'ready'
    );

    appendLog(
      `Secure file sent to ${
        selectedPeerData
          ?.display_name ||
        'peer'
      }: ${file.name}`,
      'outgoing'
    );

    setStatus(
      'SECURE PACKAGE RELAYED',
      'ready'
    );

    input.value = '';
  } catch (error) {
    console.error(
      '[SFS] Send failed',
      error
    );

    setFileStatus(
      error.message ||
        'File could not be sent.',
      'error'
    );

    setStatus(
      'SECURE TRANSFER FAILED',
      'error'
    );
  } finally {
    updateActionButtons();
  }
}

async function pollMessages() {
  if (!identity) return;

  try {
    const data =
      await apiJson(
        `/api/messages?client_id=${encodeURIComponent(
          identity.clientId
        )}`
      );

    (
      data.messages || []
    ).forEach((item) => {
      appendLog(
        `Received from ${item.sender_id.slice(
          0,
          8
        )}…: ${item.message}`,
        'incoming'
      );
    });
  } catch (_) {}
}

async function pollTransfers() {
  if (!identity) return;

  try {
    const data =
      await apiJson(
        `/api/transfers?client_id=${encodeURIComponent(
          identity.clientId
        )}`
      );

    renderTransfers(
      data.transfers || []
    );
  } catch (_) {}
}

function renderTransfers(
  transfers
) {
  const list =
    $('transfer-list');

  const empty =
    $('transfer-empty');

  if (!list || !empty) {
    return;
  }

  list
    .querySelectorAll(
      '.transfer-item'
    )
    .forEach((node) =>
      node.remove()
    );

  empty.hidden =
    transfers.length !== 0;

  transfers.forEach(
    (transfer) => {
      const item =
        document.createElement(
          'li'
        );

      item.className =
        'key-item transfer-item';

      const details =
        document.createElement(
          'div'
        );

      const title =
        document.createElement(
          'h3'
        );

      title.textContent =
        transfer.filename;

      const meta =
        document.createElement(
          'p'
        );

      meta.textContent =
        `${formatBytes(
          transfer.size
        )} · encrypted package · from ${transfer.sender_id.slice(
          0,
          8
        )}…`;

      details.append(
        title,
        meta
      );

      const actions =
        document.createElement(
          'div'
        );

      actions.className =
        'transfer-actions';

      const inspectButton =
        document.createElement(
          'button'
        );

      inspectButton.type =
        'button';

      inspectButton.className =
        'secondary-button';

      inspectButton.textContent =
        'INSPECT PACKAGE';

      inspectButton.addEventListener(
        'click',
        () =>
          showPackageInspection(
            transfer.metadata,
            'Received package'
          )
      );

      const rawButton =
        document.createElement(
          'button'
        );

      rawButton.type =
        'button';

      rawButton.className =
        'secondary-button';

      rawButton.textContent =
        'DOWNLOAD RAW PACKAGE';

      rawButton.addEventListener(
        'click',
        () =>
          downloadRawPackage(
            transfer
          )
      );

      const button =
        document.createElement(
          'button'
        );

      button.type =
        'button';

      button.className =
        'send-form-button';

      button.textContent =
        'DECRYPT & VERIFY';

      button.addEventListener(
        'click',
        () =>
          receiveSecureTransfer(
            transfer
          )
      );

      actions.append(
        inspectButton,
        rawButton,
        button
      );

      item.append(
        details,
        actions
      );

      list.appendChild(
        item
      );
    }
  );
}

function showPackageInspection(
  metadata,
  title = 'Package inspection'
) {
  const box =
    $('package-inspection');

  const content =
    $('package-inspection-content');

  if (!box || !content) {
    return;
  }

  content.replaceChildren();

  const rows = [
    [
      'Format',
      metadata.format,
    ],

    [
      'File',
      metadata.file_name,
    ],

    [
      'File size',
      formatBytes(
        metadata.file_size
      ),
    ],

    [
      'Sender',
      metadata.sender_id,
    ],

    [
      'Recipient',
      metadata.recipient_id,
    ],

    [
      'File encryption',
      metadata.file_encryption,
    ],

    [
      'Key encryption',
      metadata.key_encryption,
    ],

    [
      'Hash',
      metadata.hash_algorithm,
    ],

    [
      'Signature',
      metadata.signature_algorithm,
    ],

    [
      'Ciphertext',
      formatBytes(
        metadata.ciphertext_size
      ),
    ],

    [
      'Nonce',
      `${metadata.nonce_size} bytes`,
    ],

    [
      'GCM tag',
      `${metadata.tag_size} bytes`,
    ],

    [
      'Encrypted AES key',
      `${metadata.encrypted_aes_key_size} bytes`,
    ],

    [
      'Signature size',
      `${metadata.signature_size} bytes`,
    ],

    [
      'SHA-256',
      metadata.sha256,
    ],
  ];

  const heading =
    document.createElement(
      'h3'
    );

  heading.textContent =
    title;

  content.appendChild(
    heading
  );

  rows.forEach(
    ([label, value]) => {
      const row =
        document.createElement(
          'div'
        );

      row.className =
        'inspection-row';

      const labelNode =
        document.createElement(
          'span'
        );

      labelNode.textContent =
        label;

      const valueNode =
        document.createElement(
          'code'
        );

      valueNode.textContent =
        String(
          value ?? '—'
        );

      row.append(
        labelNode,
        valueNode
      );

      content.appendChild(
        row
      );
    }
  );

  box.hidden =
    false;

  box.scrollIntoView({
    behavior: 'smooth',
    block: 'nearest',
  });
}

async function downloadRawPackage(
  transfer
) {
  try {
    const response =
      await fetch(
        `/api/transfers/${encodeURIComponent(
          transfer.transfer_id
        )}/raw?client_id=${encodeURIComponent(
          identity.clientId
        )}`
      );

    if (!response.ok) {
      let message =
        `Raw package download failed (${response.status})`;

      try {
        const data =
          await response.json();

        message =
          data.error ||
          message;
      } catch (_) {}

      throw new Error(
        message
      );
    }

    const blob =
      await response.blob();

    const filename =
      `${transfer.filename}.sfs.json`;

    const url =
      URL.createObjectURL(
        blob
      );

    const link =
      document.createElement(
        'a'
      );

    link.href =
      url;

    link.download =
      filename;

    document.body.appendChild(
      link
    );

    link.click();

    link.remove();

    setTimeout(
      () =>
        URL.revokeObjectURL(
          url
        ),
      1000
    );

    setFileStatus(
      `Raw encrypted package downloaded: ${filename}`,
      'ready'
    );

    logCrypto(
      '[PACKAGE] Raw package downloaded',
      {
        transfer_id:
          transfer.transfer_id,

        filename,

        note:
          'Contains ciphertext and wrapped AES key; no plaintext AES key or private key.',
      }
    );
  } catch (error) {
    console.error(
      '[SFS] Raw package download failed',
      error
    );

    setFileStatus(
      error.message ||
        'Could not download the raw package.',
      'error'
    );
  }
}

async function receiveSecureTransfer(
  transfer
) {
  try {
    setStatus(
      `RECEIVING · ${transfer.filename}`,
      'ready'
    );

    const packageData =
      await apiJson(
        `/api/transfers/${encodeURIComponent(
          transfer.transfer_id
        )}?client_id=${encodeURIComponent(
          identity.clientId
        )}`
      );

    showPackageInspection(
      packageMetadataFromPackage(
        packageData
      ),
      'Received package'
    );

    logCrypto(
      `RECEIVE · ${packageData.file_name}`
    );

    logCrypto(
      '[1/6] Encrypted package received',
      {
        format:
          packageData.format,

        package_bytes:
          JSON.stringify(
            packageData
          ).length,
      }
    );

    if (
      packageData.recipient_id !==
      identity.clientId
    ) {
      throw new Error(
        'This package is addressed to a different browser identity.'
      );
    }

    const senderPeer =
      await findPeer(
        packageData.sender_id
      );

    if (!senderPeer) {
      throw new Error(
        'Sender is no longer connected; its registered public key is unavailable.'
      );
    }

    const senderKeys =
      await getPeerPublicKeys(
        senderPeer
      );

    const encryptedAesKey =
      base64ToBytes(
        packageData.encrypted_aes_key
      );

    const rawAesKey =
      new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name:
              'RSA-OAEP',
          },

          identity
            .keyPairs
            .encryption
            .privateKey,

          encryptedAesKey
        )
      );

    if (
      rawAesKey.length !==
      AES_KEY_BYTES
    ) {
      throw new Error(
        'Recovered AES key is not 256 bits.'
      );
    }

    const aesKey =
      await crypto.subtle.importKey(
        'raw',
        rawAesKey,
        {
          name:
            'AES-GCM',
        },
        false,
        ['decrypt']
      );

    logCrypto(
      '[2/6] RSA-OAEP-SHA256 AES key recovered',
      {
        bytes:
          rawAesKey.length,
      }
    );

    const ciphertext =
      base64ToBytes(
        packageData.ciphertext
      );

    const nonce =
      base64ToBytes(
        packageData.nonce
      );

    const tag =
      base64ToBytes(
        packageData.tag
      );

    const encryptedWithTag =
      new Uint8Array(
        ciphertext.length +
          tag.length
      );

    encryptedWithTag.set(
      ciphertext,
      0
    );

    encryptedWithTag.set(
      tag,
      ciphertext.length
    );

    const plaintext =
      new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name:
              'AES-GCM',

            iv:
              nonce,

            tagLength:
              128,
          },

          aesKey,

          encryptedWithTag
        )
      );

    logCrypto(
      '[3/6] AES-256-GCM authentication + decryption passed',
      {
        bytes:
          plaintext.length,
      }
    );

    const digest =
      await sha256(
        plaintext
      );

    const digestHex =
      bytesToHex(
        digest
      );

    const hashMatches =
      digestHex ===
      packageData.sha256;

    logCrypto(
      '[4/6] SHA-256',
      {
        expected:
          packageData.sha256,

        received:
          digestHex,

        match:
          hashMatches,
      }
    );

    if (!hashMatches) {
      throw new Error(
        'SHA-256 verification failed. The file or package was modified.'
      );
    }

    const signature =
      base64ToBytes(
        packageData.signature
      );

    const signatureValid =
      await crypto.subtle.verify(
        {
          name:
            'RSA-PSS',

          saltLength:
            RSA_PSS_SALT_BYTES,
        },

        senderKeys.signing,

        signature,

        digest
      );

    logCrypto(
      '[5/6] RSA-PSS-SHA256 signature verification',
      {
        valid:
          signatureValid,
      }
    );

    if (!signatureValid) {
      throw new Error(
        'Digital signature verification failed. The sender could not be authenticated.'
      );
    }

    logCrypto(
      '[6/6] FILE ACCEPTED',
      {
        filename:
          packageData.file_name,

        bytes:
          plaintext.length,
      }
    );

    downloadBytes(
      plaintext,
      packageData.file_name
    );

    appendLog(
      `Verified and received: ${packageData.file_name}`,
      'incoming'
    );

    setStatus(
      'FILE ACCEPTED · CRYPTOGRAPHY VERIFIED',
      'ready'
    );

    setFileStatus(
      `Accepted ${packageData.file_name}: AES-GCM, SHA-256 and RSA-PSS verification passed.`,
      'ready'
    );

    await pollTransfers();
  } catch (error) {
    console.error(
      '[SFS] Receive failed',
      error
    );

    setStatus(
      'FILE REJECTED · VERIFICATION FAILED',
      'error'
    );

    setFileStatus(
      error.message ||
        'Secure file could not be verified.',
      'error'
    );
  }
}

function packageMetadataFromPackage(
  packageData
) {
  return {
    format:
      packageData.format,

    file_name:
      packageData.file_name,

    file_size:
      packageData.file_size,

    sender_id:
      packageData.sender_id,

    recipient_id:
      packageData.recipient_id,

    file_encryption:
      packageData.file_encryption,

    key_encryption:
      packageData.key_encryption,

    hash_algorithm:
      packageData.hash_algorithm,

    signature_algorithm:
      packageData.signature_algorithm,

    ciphertext_size:
      packageData.ciphertext_size,

    nonce_size:
      packageData.nonce_size,

    tag_size:
      packageData.tag_size,

    encrypted_aes_key_size:
      packageData.encrypted_aes_key_size,

    signature_size:
      packageData.signature_size,

    sha256:
      packageData.sha256,
  };
}

async function findPeer(
  clientId
) {
  if (
    selectedPeerData?.client_id ===
    clientId
  ) {
    return selectedPeerData;
  }

  const data =
    await apiJson(
      `/api/peers?client_id=${encodeURIComponent(
        identity.clientId
      )}`
    );

  return (
    data.peers || []
  ).find(
    (peer) =>
      peer.client_id ===
      clientId
  ) || null;
}

function downloadBytes(
  bytes,
  filename
) {
  const blob =
    new Blob(
      [bytes],
      {
        type:
          'application/octet-stream',
      }
    );

  const url =
    URL.createObjectURL(
      blob
    );

  const link =
    document.createElement(
      'a'
    );

  link.href =
    url;

  link.download =
    filename;

  document.body.appendChild(
    link
  );

  link.click();

  link.remove();

  setTimeout(
    () =>
      URL.revokeObjectURL(
        url
      ),
    1000
  );
}

function formatBytes(
  bytes
) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (
    bytes <
    1024 * 1024
  ) {
    return `${(
      bytes / 1024
    ).toFixed(1)} KB`;
  }

  return `${(
    bytes /
    (1024 * 1024)
  ).toFixed(1)} MB`;
}

function initialize() {
  $('browser-origin').textContent =
    window.location.origin;

  getDisplayName()
    .then((name) => {
      if (
        $('display-name')
      ) {
        $('display-name').value =
          name;
      }
    })
    .catch(() => {});

  if (!window.isSecureContext) {
    setStatus(
      'HTTPS REQUIRED FOR BROWSER CRYPTO',
      'error'
    );

    return;
  }

  if (
    !window.crypto?.subtle ||
    !window.indexedDB
  ) {
    setStatus(
      'Required browser Web APIs unavailable',
      'error'
    );

    return;
  }

  (async () => {
    try {
      await register();

      await refreshPeers();

      await pollMessages();

      await pollTransfers();

      pollTimer =
        window.setInterval(
          async () => {
            await refreshPeers();

            await pollMessages();

            await pollTransfers();
          },
          2000
        );
    } catch (error) {
      setStatus(
        error.message ||
          'Could not connect to the Flask server',
        'error'
      );

      console.error(
        '[SFS] Initialization failed',
        error
      );
    }
  })();
}

document.addEventListener(
  'DOMContentLoaded',
  () => {
    $('send-test')?.addEventListener(
      'click',
      sendTestMessage
    );

    $('send-file')?.addEventListener(
      'click',
      sendFile
    );

    $('save-name')?.addEventListener(
      'click',
      saveDisplayName
    );

    initialize();
  }
);