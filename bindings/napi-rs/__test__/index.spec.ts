import test from 'ava'

import { keygen, encryptPassword, decryptPassword } from '../index'

test('should encrypt and decrypt passwords in a roundtrip', (t) => {
  const masterPassword = 'secret';
  const testPassword = 'test';

  const masterPasswordBytes = Buffer.from(masterPassword);
  const testPasswordBytes = Buffer.from(testPassword);

  const keypair = keygen();
  const encryptedPassword = encryptPassword(masterPasswordBytes, keypair.encryptionKey, testPasswordBytes);
  const decryptedPassword = decryptPassword(masterPasswordBytes, keypair.decryptionKey, encryptedPassword);

  const decryptedPasswordStr = decryptedPassword.toString();

  t.is(decryptedPasswordStr, testPassword);
});
