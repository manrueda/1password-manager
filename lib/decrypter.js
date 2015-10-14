var crypto = require('crypto');
module.exports = function(content, contentKey, masterKey, iterations){
  var master = new Buffer(masterKey);
  var keyBuf = new Buffer(contentKey, 'base64');
  var passwordBuf = new Buffer(content, 'base64');

  var keySalt = keyBuf.slice(8, 16);
  var keyData = keyBuf.slice(16);

  var derivedKey = crypto.pbkdf2Sync(master, keySalt, iterations, 32);

  var AESKey = derivedKey.slice(0, 16);
  var AESIv = derivedKey.slice(16, 32);

  var keyRaw = decrypt(keyData, AESKey, AESIv);

  var passwordSalt = passwordBuf.slice(8, 16);
  var passwordData = passwordBuf.slice(16);

  var passwordAux = deriveKey(keyRaw, passwordSalt);
  var passwordKey = passwordAux.key;
  var passwordIv = passwordAux.iv;

  return JSON.parse(decrypt(passwordData, passwordKey, passwordIv));
};

function decrypt(data, key, iv){
  var cipher = crypto.createDecipheriv('aes-128-cbc', key, iv);

  var upBuf = cipher.update(data);
  var finBuf = cipher.final();

  return Buffer.concat([upBuf, finBuf]);
}

function deriveKey(key, salt){
  var rounds = 2;
  var data = Buffer.concat([key, salt]);
  var md5Hashes = [[],[]];
  var md5sum = crypto.createHash('md5');
  md5sum.update(data);
  var sum = md5sum.digest();
  md5Hashes[0] = sum;
  for(var i = 1; i < rounds; i++){
    md5sum = crypto.createHash('md5');
    md5sum.update(Buffer.concat([md5Hashes[i - 1], data]));
    sum = md5sum.digest();
    md5Hashes[i] = sum;
  }
  return {
    key:md5Hashes[0],
    iv: md5Hashes[1]
  };

}
