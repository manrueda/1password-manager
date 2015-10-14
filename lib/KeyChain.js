var ZipMapper = require('zip-mapper');
var decrypter = require('./decrypter');

module.exports = function KeyChain(path, profile, cb) {
  if (profile instanceof Function){
    cb = profile;
    profile = 'default';
  }

  var that = this;
  var masterKey;

  that.profile = profile;
  var encryptionKeys = null;
  //var contentsData = null;
  that.contents = [];

  ZipMapper(path, true, function(err, map){
    parseBasic(map);
    parseContents(map);
    if (cb){
      cb(that);
    }
  });

  this.setMasterKey = function(key){
    masterKey = key;
    return this;
  };

  this.decryptContent = function(contentUUID){
    var content = that.contents.filter(function(c){
      return c.uuid === contentUUID;
    })[0];

    var key = encryptionKeys.list.filter(function(c){
      return c.identifier === content.keyID;
    })[0];

    return decrypter(content.encrypted, key.data, masterKey, key.iterations);
  };

  //Parse the encryption keys and content data
  function parseBasic(map){
    encryptionKeys = JSON.parse(map.data[that.profile]['encryptionKeys.js'].toString('UTF-8'));
  }

  function parseContents(map){
    var keys = Object.keys(map.data[that.profile]);
    keys = keys.filter(function(c){
      return c.endsWith('.1password');
    });
    keys.forEach(function(k){
      that.contents.push(JSON.parse(map.data[that.profile][k].toString('UTF-8')));
    });
  }

  return this;
};
