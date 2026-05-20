const test = require('node:test');
const assert = require('node:assert/strict');

const { createDeviceManagementService } = require('../src/modules/devices/application/deviceManagementService');

function makeDeviceModel(docs) {
  return {
    find(query) {
      return {
        lean: async () =>
          docs.filter(
            (doc) =>
              doc.parentUserId === query.parentUserId &&
              doc.isRevoked === query.isRevoked
          ),
      };
    },
    updateOne: async () => ({}),
  };
}

const keyedDevice = {
  publicIdentityKeyX25519: 'ik-x',
  publicIdentityKeyEd25519: 'ik-ed',
  signedPreKey: 'spk',
  signedPreKeySignature: 'sig',
};

test('listDevices hides unsynced secondary devices without uploaded key bundles', async () => {
  const service = createDeviceManagementService({
    Device: makeDeviceModel([
      {
        deviceId: 'primary',
        parentUserId: 'U1',
        deviceUserId: 'alice_primary',
        isPrimary: true,
        isRevoked: false,
      },
      {
        deviceId: 'synced-phone',
        parentUserId: 'U1',
        deviceUserId: 'alice_x1',
        isPrimary: false,
        isRevoked: false,
        ...keyedDevice,
      },
      {
        deviceId: 'crashed-phone',
        parentUserId: 'U1',
        deviceUserId: 'alice_x2',
        isPrimary: false,
        isRevoked: false,
      },
      {
        deviceId: 'revoked-phone',
        parentUserId: 'U1',
        deviceUserId: 'alice_x3',
        isPrimary: false,
        isRevoked: true,
        ...keyedDevice,
      },
    ]),
    MessageEnvelope: {},
    User: {},
  });

  const devices = await service.listDevices({ parentUserId: 'U1' });

  assert.deepEqual(
    devices.map((device) => device.deviceId),
    ['primary', 'synced-phone']
  );
  assert.equal(devices.find((device) => device.deviceId === 'primary').isSynced, false);
  assert.equal(devices.find((device) => device.deviceId === 'synced-phone').isSynced, true);
});

test('getDeviceBundles skips devices that are not ready for sync fanout', async () => {
  const service = createDeviceManagementService({
    Device: makeDeviceModel([
      {
        deviceId: 'synced-phone',
        parentUserId: 'U1',
        deviceUserId: 'alice_x1',
        isPrimary: false,
        isRevoked: false,
        ...keyedDevice,
      },
      {
        deviceId: 'crashed-phone',
        parentUserId: 'U1',
        deviceUserId: 'alice_x2',
        isPrimary: false,
        isRevoked: false,
      },
    ]),
    MessageEnvelope: {},
    User: {},
  });

  const bundles = await service.getDeviceBundles({ parentUserId: 'U1' });

  assert.deepEqual(
    bundles.map((bundle) => bundle.deviceId),
    ['synced-phone']
  );
});
