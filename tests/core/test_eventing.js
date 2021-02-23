const { Signer, init_libsodium } = require('../../src/keri/core/signer')
var libsodium = require('libsodium-wrappers-sumo')
const assert = require('assert').strict;
const derivationCodes = require('../../src/keri/core/derivationCode&Length')
let { TraitCodex } = require('../../src/keri/eventing/TraitCodex')
let { Kever } = require('../../src/keri/eventing/Kever')
let { Kevery } = require('../../src/keri/eventing/kevery')
const { Nexter } = require('../../src/keri/core/nexter')
const { Serder } = require('../../src/keri/core/serder')
const { Sigcounter } = require('../../src/keri/core/SigCounter')
const { Prefixer } = require('../../src/keri/core/prefixer')
const { SealEvent, LastEstLoc } = require('../../src/keri/eventing/util')
const { versify, Serials, Versionage, Ilks, Vstrings, Serialage } = require('../../src/keri/core/core');
//const { Logger } = require('../../src/keri/db/database');
const { openLogger, Logger, snkey, dgkey, openDatabaser } = require('../../src/keri/db/database');
const { bindAll } = require('lodash');
const blake3 = require('blake3');
const SigCounter = require('../../src/keri/core/SigCounter');
const { deepStrictEqual } = require('assert');
/**
 * @description Test the support functionality for key event generation functions
 */
async function test_keyeventfuncs() {


  let seed = '\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\xc9\xbd\x04\x9d\x85)~\x93'
  seed = Buffer.from(seed, 'binary')
  console.log("Seed is -------->", seed)

  // # Inception: Non-transferable (ephemeral) case
  await libsodium.ready
  let signer0 = new Signer(seed, derivationCodes.oneCharCode.Ed25519_Seed, false, libsodium)
  //    let signer0 =  new  Signer(seed,null,false)  // original signing keypair non transferable

  //     assert.deepStrictEqual(signer0.code(),derivationCodes.oneCharCode.Ed25519_Seed)
  //     console.log("Case successfully tested")
  let ver_ = signer0.verfer()
  //     assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519N)
  let key0 = [ver_.qb64()]
  let Trait_instance = new TraitCodex()

  let serder = Trait_instance.incept(key0)
  //   serder.set_raw()
  let ked = serder.ked()
  serder.set_ked(ked)
  // console.log("Serder.raw ---------->",(serder.raw()).toString())
  let response = '{"vs":"KERI10JSON0000cf_","pre":"Bn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM","sn":"0","ilk":"icp","sith":"1","keys":["Bn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM"],"nxt":"","toad":"0","wits":[],"cnfg":[]}'
  response = Buffer.from(response, 'binary')
  assert.deepStrictEqual(serder.ked()['pre'], 'Bn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM')
  assert.deepStrictEqual(serder.ked()['nxt'], '')
  console.log("Case successfully tested", (serder.raw()).toString())

  assert.deepStrictEqual(serder.raw(), response)





  //# # Inception: Transferable Case but abandoned in incept so equivalent
  signer0 = new Signer(seed, derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium) //# original signing keypair transferable default
  ver_ = signer0.verfer()
  key0 = [ver_.qb64()]
  Trait_instance = new TraitCodex()

  serder = Trait_instance.incept(key0)

  //   serder.set_raw()
  ked = serder.ked()
  serder.set_ked(ked)
  // assert.deepStrictEqual(signer0.code(),derivationCodes.oneCharCode.Ed25519_Seed)
  // assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519)


  // // assert.deepStrictEqual(serder.ked()['pre'], 'Dn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM')
  // // assert.deepStrictEqual(serder.ked()['nxt'], '')
  // let response1 = '{"vs":"KERI10JSON0000cf_","pre":"Dn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM","sn":"0","ilk":"icp","sith":"1","keys":["Dn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM"],"nxt":"","toad":"0","wits":[],"cnfg":[]}'
  // response1 = Buffer.from(response1 , 'binary')
  // assert.deepStrictEqual(serder.raw(),response1)











  //# # Inception: Transferable not abandoned i.e. next not empty
  let seed2 = `\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015\x98Y\xdd\xe8`
  seed2 = Buffer.from(seed2, 'binary')
  let signer1 = new Signer(seed2, derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium)  // next signing keypair transferable is default


  ver_ = signer1.verfer()
  let key1 = [ver_.qb64()]
  Trait_instance = new TraitCodex()
  let nexter1 = new Nexter(null, null, key1)       //# dfault sith is 1
  let nxt1 = nexter1.qb64()  //# transferable so nxt is not empty

  //     assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519N)

  //  keys=keys0, nxt=nxt1
  let serder1 = Trait_instance.incept(key1, null, Versionage, Serials.json, null, nxt1)

  ked = serder1.ked()
  serder1.set_ked(ked)
  console.log("Value of pre is -------------->", serder1.ked()['pre'])

  //    assert.deepStrictEqual(signer1.code(),derivationCodes.oneCharCode.Ed25519_Seed)
  //    assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519)
  //    assert.deepStrictEqual(nexter1.sith(),'1') //# default from keys
  //    assert.deepStrictEqual(nxt1,'EluSZyeNzaFHLOFVB8tD1HFsnI6NQ7BxoDe1DNF-xZRA')
  // assert.deepStrictEqual(serder1.ked()["pre"],'Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg')
  // assert.deepStrictEqual(serder1.ked()["sn"],'0')
  // assert.deepStrictEqual(serder1.ked()["ilk"],Ilks.icp)
  // assert.deepStrictEqual(serder1.ked()["nxt"],nxt1)


  //   let response2 = '{"vs":"KERI10JSON0000fb_","pre":"Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg","sn":"0","ilk":"icp","sith":"1","keys":["Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg"],"nxt":"EluSZyeNzaFHLOFVB8tD1HFsnI6NQ7BxoDe1DNF-xZRA","toad":"0","wits":[],"cnfg":[]}'
  //   response2 = Buffer.from(response2 , 'binary')
  //   assert.deepStrictEqual(serder1.raw(),response2)
  //   assert.deepStrictEqual(serder1.dig(),'EQhXAyg_A_8vbkQ6erwK5d9_QdyNdnB8e9fU6xQXeoXA')
  // # assert serder0.dig == 





  //# # Rotation: Transferable not abandoned i.e. next not empty
  //# # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
  let seed3 = `\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2e\xf9AL\x1aeK\xafj\xa1pB`



  seed3 = Buffer.from(seed3, 'binary')
  let signer2 = new Signer(seed3, derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium)  // next signing keypair transferable is default


  ver_ = signer2.verfer()
  let key2 = [ver_.qb64()]
  Trait_instance = new TraitCodex()
  let nexter2 = new Nexter(null, null, key2)       //# dfault sith is 1
  let nxt2 = nexter2.qb64()  //# transferable so nxt is not empty
  let pre = serder1.ked()["pre"]
  let serder2 = Trait_instance.rotate(pre, key1, serder1.dig(), 1, Versionage, Serials.json, null, nxt2)
  //     assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519N)

  //  keys=keys0, nxt=nxt1
  //let serder2 = Trait_instance.incept(key2,null,Versionage,Serials.json,null,nxt2)
  //   serder.set_raw()
  ked = serder2.ked()
  serder2.set_ked(ked)




  assert.deepStrictEqual(signer2.code(), derivationCodes.oneCharCode.Ed25519_Seed)
  assert.deepStrictEqual(ver_.code(), derivationCodes.oneCharCode.Ed25519)
  assert.deepStrictEqual(nexter2.sith(), '1') //# default from keys
  assert.deepStrictEqual(nxt2, 'EnpCDk0g_k6TGr2rr4F279Si5BucM_Yi4xkffB2XDQOE')
  assert.deepStrictEqual(serder2.ked()["pre"], 'Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg')
  assert.deepStrictEqual(serder2.ked()["sn"], '1')
  assert.deepStrictEqual(serder2.ked()["ilk"], Ilks.rot)
  assert.deepStrictEqual(serder2.ked()["nxt"], nxt2)


  let response3 = '{"vs":"KERI10JSON00013c_","pre":"Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg","sn":"1","ilk":"rot","dig":"EQhXAyg_A_8vbkQ6erwK5d9_QdyNdnB8e9fU6xQXeoXA","sith":"1","keys":["Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg"],"nxt":"EnpCDk0g_k6TGr2rr4F279Si5BucM_Yi4xkffB2XDQOE","toad":"0","cuts":[],"adds":[],"data":null}'
  response3 = Buffer.from(response3, 'binary')
  assert.deepStrictEqual(serder2.raw(), response3)
  assert.deepStrictEqual(serder2.dig(), 'EV8sa4Hb8ItAXOxFyrNIOwSbFQPW02-lljSrlK0mARZ4')



  //# # Interaction:
  let serder3 = Trait_instance.interact(pre, serder2.dig(), 2)

  ked = serder3.ked()
  serder3.set_ked(ked)

  assert.deepStrictEqual(serder3.ked()["pre"], pre)
  assert.deepStrictEqual(serder3.ked()["sn"], '2')
  assert.deepStrictEqual(serder3.ked()["ilk"], Ilks.ixn)
  assert.deepStrictEqual(serder3.ked()["dig"], serder2.dig())


  let response4 = '{"vs":"KERI10JSON0000a3_","pre":"Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg","sn":"2","ilk":"ixn","dig":"EV8sa4Hb8ItAXOxFyrNIOwSbFQPW02-lljSrlK0mARZ4","data":[]}'
  response4 = Buffer.from(response4, 'binary')
  assert.deepStrictEqual(serder3.raw(), response4)



  //# # Receipt
  let serder4 = Trait_instance.receipt(pre, 0, serder3.dig())


  ked = serder4.ked()
  serder4.set_ked(ked)
  let response5 = '{"vs":"KERI10JSON000099_","pre":"Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg","ilk":"rct","sn":"0","dig":"EeBYyZMpdNp0vIPjSUdihy9U8GV-mM4ri8873a0hT4Lo"}'
  response5 = Buffer.from(response5, 'binary')

  assert.deepStrictEqual(serder4.ked()["pre"], pre)
  assert.deepStrictEqual(serder4.ked()["sn"], '0')
  assert.deepStrictEqual(serder4.ked()["ilk"], Ilks.rct)
  assert.deepStrictEqual(serder4.ked()["dig"], serder3.dig())
  assert.deepStrictEqual(serder4.raw(), response5)



  //# # ValReceipt  chit
  let serderA = Trait_instance.incept(key0, derivationCodes.oneCharCode.Blake3_256, Versionage, Serials.json, null, nxt1)
  ked = serderA.ked()
  serderA.set_ked(ked)

  SealEvent.dig = serderA.dig()
  SealEvent.pre = serderA.ked()["pre"]

  assert.deepStrictEqual(serderA.ked()["pre"], 'ErxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI')
  assert.deepStrictEqual(SealEvent.pre, serderA.ked()["pre"])

  assert.deepStrictEqual(serderA.ked()["pre"], 'ErxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI')
  assert.deepStrictEqual(SealEvent.dig, serderA.dig())

  let response6 = '{"vs":"KERI10JSON0000fb_","pre":"ErxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI","sn":"0","ilk":"icp","sith":"1","keys":["Dn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM"],"nxt":"EluSZyeNzaFHLOFVB8tD1HFsnI6NQ7BxoDe1DNF-xZRA","toad":"0","wits":[],"cnfg":[]}'
  response6 = Buffer.from(response6, 'binary')

  assert.deepStrictEqual(serderA.raw(), response6)




  let serder5 = Trait_instance.chit(pre, 2, serder4.dig(), SealEvent)

  ked = serder5.ked()
  serder5.set_ked(ked)
  assert.deepStrictEqual(serder5.ked()["pre"], pre)
  assert.deepStrictEqual(serder5.ked()["ilk"], Ilks.vrc)
  assert.deepStrictEqual(serder5.ked()["sn"], "2")
  assert.deepStrictEqual(serder5.ked()["dig"], serder4.dig())
  assert.deepStrictEqual(serder5.ked()["seal"], SealEvent)
  // # assert 
  // # assert serder5.raw == (b'{"vs":"KERI10JSON00010c_","pre":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
  // #                        b'c","ilk":"vrc","sn":"2","dig":"EEWroCdb9ARV9R35eM-gS4-5BPPvBXRQU_P89qlhET7E"'
  // #                        b',"seal":{"pre":"EyqftoqSC_ANDHdx9v4sygNas8Wvy3szYSuTxjT0lvzs","dig":"EBk2aGu'
  // #                        b'L5oHsF64QNAeEPEal-JBYJLe5GvXqp3mLMFKw"}}')
}

async function test_kever() {

  // # Transferable case
  // # Setup inception key event dict
  // # create current key
  let lgr = new Logger()
  await libsodium.ready
  let sith = 1
  let skp0 = new Signer(Buffer.from('', 'binary'), derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium)
  let _ver = skp0.verfer()
  let keys = [_ver.qb64()]
  //   assert.deepStrictEqual(skp0.code(),derivationCodes.oneCharCode.Ed25519_Seed)
  //  console.log("test successfully run")
  //  assert.deepStrictEqual(_ver.code(),derivationCodes.oneCharCode.Ed25519)


  //# create next key

  let nxtsith = 1  // # one signer
  let skp1 = new Signer(Buffer.from('', 'binary'), derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium)
  _ver = skp1.verfer()
  let nxtkeys = [_ver.qb64()]
  //  assert.deepStrictEqual(skp0.code(),derivationCodes.oneCharCode.Ed25519_Seed)
  //  assert.deepStrictEqual(_ver.code(),derivationCodes.oneCharCode.Ed25519)




  let nexter = new Nexter(null, nxtsith, nxtkeys, null)
  let nxt = nexter.qb64()  //# transferable so nxt is not empty

  let sn = 0     //# inception event so 0
  let toad = 0   //# no witnesses
  let nsigs = 1    //# one attached signature unspecified index
  let vs = versify(Versionage, Serials.json, 0)
  let ked0 = {
    vs: vs.toString(),         // version string
    pre: "",                                       //# qb64 prefix
    sn: sn.toString(16),             // # hex string no leading zeros lowercase
    ilk: Ilks.icp,
    sith: sith.toString(16),              //# hex string no leading zeros lowercase
    keys: keys,                            //# list of qb64
    nxt: nxt,                              //# hash qual Base64
    toad: toad.toString(16),             //  # hex string no leading zeros lowercase
    wits: [],                            // # list of qb64 may be empty
    cnfg: [],
    // # list of config ordered mappings may be empty
  }


  // # Derive AID from ked
  let aid0 = new Prefixer(null, derivationCodes.oneCharCode.Ed25519, ked0)
  _ver = skp0.verfer()
  console.log("DERIVED AID qb64 from KED -------------------->", aid0.qb64())

  // assert.deepStrictEqual(aid0.code(),derivationCodes.oneCharCode.Ed25519)
  // assert.deepStrictEqual(aid0.qb64(),_ver.qb64())


  // # update ked with pre
  ked0.pre = aid0.qb64()


  let tser0 = new Serder(null, ked0)
  tser0.set_ked(ked0)
  console.log("KED SERIALIZED DATA--------------->", tser0.raw())
  //  # sign serialization
  console.log("Signing Serialized KED--------------->")
  let tsig0 = await skp0.sign(tser0.raw(), 0)
  console.log("SIGNED  Serialized KED DATA--------------->", tser0)
  // # verify signature
  //  console.log("verifying Serialized KED's Signatures --------------->")
  assert.deepStrictEqual(aid0.qb64(), _ver.qb64())
  _ver.verify(tsig0._raw, tser0.raw())

  let kever = new Kever(tser0, [tsig0], null, lgr)  // # no errortser
  console.log("KEVER = ------------->", kever)


}



/**
 *  """
    Test generation of a sequence of key events

    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # root = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    # root = '0AZxWJGkCkpDcHuVG4GM1KVw'
    # rooter = CryMat(qb64=root)
    # assert rooter.qb64 == root
    # assert rooter.code == CryTwoDex.Seed_128
    # signers = generateSigners(root=rooter.raw, count=8, transferable=True)
    # secrets = [signer.qb64 for signer in signers]
    # secrets =generateSecrets(root=rooter.raw, count=8, transferable=True)

    # Test sequence of events given set of secrets
 */
async function test_keyeventsequence_0() {

  await libsodium.ready


  let secrets = [
    'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
    'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
    'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
    'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
    'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
    'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
    'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
    'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
  ]


  console.log("CREATING MULTIPLE SIGNERS: = \n")

  for (let secret in secrets) {
    var signers = [new Signer(Buffer.from('', 'binary'), derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium, secrets[secret])]

    assert.deepStrictEqual(signers[secret].qb64(), secrets[secret])
  }

}



/**
 *   """
    Test the support functionality for Kevery factory class
    Key Event Verifier Factory
    """

    # Test sequence of events given set of secrets
 */

async function test_kevery() {

  let secrets = [
    'AkWPIzjJ_4bfRRK2bQSuLIo12Gqr7SJZIItiR77kSTG8',
    'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
    'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
    'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
    'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
    'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
    'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
    'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
  ]

  let conlgr = openLogger("controller")
  let vallgr = openLogger("validator")

  let event_digs = []
  var signers = []


  await libsodium.ready
  // Creating Signers



  for (let secret in secrets) {
    signers[secret] = new Signer(Buffer.from('', 'binary'), derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium, secrets[secret])

  }
  //  let s_ = Promise.all(signers).then(()=>{
  //    for(){}
  //  })
  // # Event 0  Inception Transferable (nxt digest not empty)


  let Trait_instance = new TraitCodex()
  console.log("List of signers are ============+>", signers[1])

  //   serder.set_raw()


  let ver_ = signers[0].verfer()
  let ver1_ = signers[1].verfer()
  let key0 = [ver_.qb64()]
  let key1 = [ver1_.qb64()]
  let nexter = new Nexter(null, null, key1)
  let serder = Trait_instance.incept(key0, null, Versionage, Serials.json, null, nexter.qb64())
  let ked = serder.ked()

  serder.set_ked(ked)

  event_digs.push(serder.dig())
  console.log("Event 0 is ------------------_>", event_digs)
  // # create sig counter
  let counter = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)        // # default is count = 1
  // # sign serialization
  let siger = await signers[0].sign(serder.raw(), 0)      // # return siger
  //create key event verifier state

  let kever = new Kever(serder, [siger], null, conlgr)
  console.log("key event verifier state : ", kever)

  //extend key event stream
  let arr = [Buffer.from(serder.raw(), 'binary'),
  Buffer.from(counter.qb64b(), 'binary'),
  Buffer.from(siger.qb64b(), 'binary')]

  let arr1 = Buffer.concat(arr)
  //  kes.extend(serder.raw)
  //  kes.extend(counter.qb64b)
  //  kes.extend(siger.qb64b())
  console.log("arr ====================+>", arr.toString())

  let response = `{"vs":"KERI10JSON0000fb_","pre":"Dtu-93oDK-wWwYzkLavqFcYBrLCBrzErKoIy0RH2BAC4","sn":"0","ilk":"icp","sith":"1","keys":["Dtu-93oDK-wWwYzkLavqFcYBrLCBrzErKoIy0RH2BAC4"],"nxt":"EgQeml4TwX51cTmThEzH-3LFooXkaq50kvZcR5eh_a3k","toad":"0","wits":[],"cnfg":[]}`
  // response = Buffer.from(response,'binary')
  // assert.deepStrictEqual(arr.toString(),response)

  let _res = kever.diger
  console.log("Value of _res is ========>", _res.qb64())
  let ver2_ = signers[2].verfer()
  let ver3_ = signers[3].verfer()
  let ver4_ = signers[4].verfer()
  let ver5_ = signers[5].verfer()






  // # Event 1 Rotation Transferable
  let serder1 = Trait_instance.rotate(kever.prefixer.qb64(),
    [ver1_.qb64()],
    kever.diger.qb64(), 1, Versionage,
    Serials.json,
    null,
    new Nexter(null, null, [ver2_.qb64()]).qb64(),
  )

  ked = serder1.ked()
  serder1.set_ked(ked)

  arr.push(Buffer.from(serder1.dig, 'binary'))
  //#     event_digs.append(serder.dig)
  //    # create sig counter
  let counter1 = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)     // # default is count = 1
  //     # sign serialization
  let siger1 = await signers[1].sign(serder1.raw(), 0) // # returns siger
  console.log("Value of siger is ====================>", (serder1.raw()).length)
  // # update key event verifier state
  await kever.update(serder1, [siger1])
  // # extend key event stream
  console.log("KEVEr successfully updated ================>")
  let arr2 = [Buffer.from(serder1.raw(), 'binary'),
  Buffer.from(counter1.qb64b(), 'binary'),
  Buffer.from(siger1.qb64b(), 'binary')
  ]
  arr2 = Buffer.concat(arr2)
  console.log('Event 1  Inception Transferable (nxt digest not empty) =========>', arr2.toString())



  //     # Event 2 Rotation Transferable




  //   let Trait_instance1 = new TraitCodex()
  let serder2 = Trait_instance.rotate(kever.prefixer.qb64(),
    [ver2_.qb64()],
    kever.diger.qb64(), 2, Versionage,
    Serials.json,
    null,
    new Nexter(null, null, [ver3_.qb64()]).qb64(),
  )



  ked = serder2.ked()
  console.log("SERDER1.ked is =============>", ked)
  serder2.set_ked(ked)


  //   //   #     # create sig counter
  let counter2 = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)    // # default is count = 1
  //   //  #     # sign serialization
  let siger2 = await signers[2].sign(serder2.raw(), 0)
  //   // #     # update key event verifier state
  //  // let kever1 = new Kever(serder1, [siger1], null, conlgr)
  await kever.update(serder2, [siger2])
  //   // #     # extend key event stream
  let arr3 = [Buffer.from(serder2.raw(), 'binary'),
  Buffer.from(counter2.qb64b(), 'binary'),
  Buffer.from(siger2.qb64b(), 'binary')
  ]
  arr3 = Buffer.concat(arr3)
  console.log('Event 2  Inception Transferable (nxt digest not empty) =========>', arr3.toString())



  // #     # Event 3 Interaction

  let serder3 = Trait_instance.interact(kever.prefixer.qb64(),
    kever.diger.qb64(), 3, Versionage,
    Serials.json)


  ked = serder3.ked()
  serder3.set_ked(ked)
  // // event_digs.append(serder.dig())
  // //#     # create sig counter
  let counter3 = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)   // # default is count = 1
  // // #     # sign serialization
  console.log("signers[2] =================>", serder3)
  let siger3 = await signers[2].sign(serder3.raw(), 0)
  // //#     # update key event verifier state
  kever.update(serder3, [siger3])
  let arr4 = [Buffer.from(serder3.raw(), 'binary'),
  Buffer.from(counter3.qb64b(), 'binary'),
  Buffer.from(siger3.qb64b(), 'binary')
  ]
  arr4 = Buffer.concat(arr4)
  console.log('Event 3  Inception Transferable (nxt digest not empty) =========>', arr4)





  // #     # Event 4 Interaction
  let serder4 = Trait_instance.interact(kever.prefixer.qb64(),
    kever.diger.qb64(), 4, Versionage,
    Serials.json)

  ked = serder4.ked()
  serder4.set_ked(ked)
  // #     # create sig counter
  let counter4 = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)   //# default is count = 1
  // #     # sign serialization
  let siger4 = await signers[2].sign(serder4.raw(), 0)
  // #     # update key event verifier state
  await kever.update(serder4, [siger4])
  // #     # extend key event stream
  let arr5 = [Buffer.from(serder4.raw(), 'binary'),
  Buffer.from(counter4.qb64b(), 'binary'),
  Buffer.from(siger4.qb64b(), 'binary')
  ]
  arr5 = Buffer.concat(arr5)
  console.log('Event 3  Inception Transferable (nxt digest not empty) =========>', arr5)



  // #     # Event 5 Rotation Transferable
  let serder5 = Trait_instance.rotate(kever.prefixer.qb64(),
    [ver3_.qb64()],
    kever.diger.qb64(), 5, Versionage,
    Serials.json,
    null,
    new Nexter(null, null, [ver4_.qb64()]).qb64(),
  )

  ked = serder5.ked()
  serder5.set_ked(ked)




  //  #     event_digs.append(serder.dig)
  //#     # create sig counter
  let counter5 = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)  //# default is count = 1
  // #     # sign serialization
  let siger5 = await signers[3].sign(serder5.raw(), 0)
  // #     # update key event verifier state
  await kever.update(serder5, [siger5])
  //#     # extend key event stream


  let arr6 = [Buffer.from(serder5.raw(), 'binary'),
  Buffer.from(counter5.qb64b(), 'binary'),
  Buffer.from(siger5.qb64b(), 'binary')
  ]
  arr6 = Buffer.concat(arr6)
  console.log('Event 4  Inception Transferable (nxt digest not empty) =========>', arr6)





  //#     # Event 6 Interaction



  let serder6 = Trait_instance.interact(kever.prefixer.qb64(),
    kever.diger.qb64(), 6, Versionage,
    Serials.json)


  ked = serder6.ked()
  serder6.set_ked(ked)
  // // event_digs.append(serder.dig())
  // //#     # create sig counter
  let counter6 = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)   // # default is count = 1
  // // #     # sign serialization
  console.log("signers[2] =================>", serder6)
  let siger6 = await signers[3].sign(serder6.raw(), 0)
  // //#     # update key event verifier state
  await kever.update(serder6, [siger6])
  let arr7 = [Buffer.from(serder6.raw(), 'binary'),
  Buffer.from(counter6.qb64b(), 'binary'),
  Buffer.from(siger6.qb64b(), 'binary')
  ]
  arr7 = Buffer.concat(arr7)
  console.log('Event 3  Inception Transferable (nxt digest not empty) =========>', arr7)








  // #     # Event 7 Rotation to null NonTransferable Abandon
  // #     # nxt digest is empty

  let serder7 = Trait_instance.rotate(kever.prefixer.qb64(),
    [ver4_.qb64()],
    kever.diger.qb64(), 7, Versionage,
    Serials.json,
    null
  )

  ked = serder7.ked()
  serder7.set_ked(ked)
  // #     # create sig counter
  let counter7 = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)          //# default is count = 1
  //#     # sign serialization
  let siger7 = await signers[4].sign(serder6.raw(), 0)
  //#     # update key event verifier state
  await kever.update(serder7, [siger7])
  //#     # extend key event stream
  let arr8 = [Buffer.from(serder7.raw(), 'binary'),
  Buffer.from(counter7.qb64b(), 'binary'),
  Buffer.from(siger7.qb64b(), 'binary')
  ]
  arr8 = Buffer.concat(arr8)
  console.log('Event 3  Inception Transferable (nxt digest not empty) =========>', arr8)




  //    # Event 8 Interaction
  let serder8 = Trait_instance.interact(kever.prefixer.qb64(),
    kever.diger.qb64(), 8, Versionage,
    Serials.json)


  ked = serder8.ked()
  serder8.set_ked(ked)
  //#     # create sig counter
  let counter8 = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)     //# default is count = 1
  // #     # sign serialization
  let siger8 = await signers[4].sign(serder8.raw(), 0)
  // #     # update key event verifier state
  // #     with pytest.raises(ValidationError):  # nontransferable so reject update
  await kever.update(serder8, [siger8])


  let arr9 = [Buffer.from(serder8.raw(), 'binary'),
  Buffer.from(counter8.qb64b(), 'binary'),
  Buffer.from(siger8.qb64b(), 'binary')
  ]
  arr9 = Buffer.concat(arr9)
  console.log('Event 3  Inception Transferable (nxt digest not empty) =========>', arr9)
  // #     # extend key event stream


  //#     # Event 8 Rotation
  let serder10 = Trait_instance.rotate(kever.prefixer.qb64(),
    [ver4_.qb64()],
    kever.diger.qb64(), 8, Versionage,
    Serials.json,
    null,
    new Nexter(null, null, [ver5_.qb64()]).qb64(),
  )




  ked = serder10.ked()
  serder10.set_ked(ked)
  //#     # create sig counter
  let counter9 = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)         //# default is count = 1
  // #     # sign serialization
  let siger10 = signers[4].sign(serder10.raw, 0)
  // #     # update key event verifier state
  // #     with pytest.raises(ValidationError):  # nontransferable so reject update
  await kever.update(serder10, sigers = [siger10])
  // #     # extend key event stream

  let arr10 = [Buffer.from(serder10.raw(), 'binary'),
  Buffer.from(counter9.qb64b(), 'binary'),
  Buffer.from(siger10.qb64b(), 'binary')
  ]
  arr10 = Buffer.concat(arr10)
  console.log('Event 3  Inception Transferable (nxt digest not empty) =========>', arr10)
}




/**
 *   """
    Test direct mode with transverable validator event receipts

    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # secrets = generateSecrets(root=root, count=8)


    #  Direct Mode initiated by coe is controller, val is validator
    #  but goes both ways once initiated.
 */
async function test_direct_mode() {


  await libsodium.ready
  let coeSigners = []
  let signers = []
  let valSigners = []
  let signers1 = []
  // # set of secrets  (seeds for private keys)
  let coeSecrets = [
    'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
    'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
    'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
    'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
    'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
    'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
    'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
    'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
  ]

  //     #  create coe signers
  for (let secret in coeSecrets) {
    //  console.log("coeSigners =======>",coeSigners)
    coeSigners[secret] = new Signer(null, derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium, coeSecrets[secret])

  }
  for (let signer in coeSigners) {
    signers[signer] = coeSigners[signer].qb64()
    assert.deepStrictEqual(signers[signer], coeSecrets[signer])
  }



  // # set of secrets (seeds for private keys)
  let valSecrets = ['AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
    'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
    'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
    'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs',
    'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
    'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
    'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc',
    'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s'
  ]


  //  #  create val signers



  for (let secret in valSecrets) {
    valSigners[secret] = new Signer(null, derivationCodes.oneCharCode.Ed25519_Seed, true, libsodium, valSecrets[secret])
  }

  for (let signer in valSigners) {
    signers1[signer] = valSigners[signer].qb64()
    assert.deepStrictEqual(signers1[signer], valSecrets[signer])
  }


  let coeLogger = openLogger("controller").next().value
  let valLogger = openLogger("validator").next().value

  //  #  init Keverys
  let coeKevery = new Kevery(null, null, null, coeLogger)
  let valKevery = new Kevery(null, null, null, valLogger)

  let coe_event_digs = []   //# list of coe's own event log digs to verify against database
  let val_event_digs = []   //# list of val's own event log digs to verify against database

  //#  init sequence numbers for both coe and vala
  let csn = cesn = 0  // # sn and last establishment sn = esn
  let vsn = vesn = 0    //# sn and last establishment sn = esn


  //# Coe Event 0  Inception Transferable (nxt digest not empty)
  let Trait_instance = new TraitCodex()

  let coe_ = coeSigners[cesn].verfer()
  let coe1_ = coeSigners[cesn + 1].verfer()

  let coeSerder = Trait_instance.incept([coe_.qb64()], derivationCodes.oneCharCode.Blake3_256
    , Versionage, Serials.json, null, new Nexter(null, null, [coe1_.qb64()]).qb64())

  let ked = coeSerder.ked()
  console.log("COSERDER KED IS :", ked)
  coeSerder.set_ked(ked)

  assert.deepStrictEqual(parseInt(coeSerder.ked()["sn"], 16), 0)
  let coepre = coeSerder.ked()['pre']
  console.log("coeSerder.ked() ==========================>",coeSerder.ked())
  assert.deepStrictEqual(coepre, 'EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E')

  coe_event_digs.push(coeSerder.dig())

  let counter = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)
  // console.log("CONTROLLER PUBLIC KEY IS ", coeSigners[cesn]._qb64)
  let siger = await coeSigners[cesn].sign(coeSerder.raw(), 0)

  // console.log("siger =====================>", counter.qb64b())
  
  // #  create serialized message
  let cmsg = [coeSerder.raw(), counter.qb64b(), siger.qb64b()]
  let cmsg_string = `{"vs":"KERI10JSON0000fb_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","wits":[],"cnfg":[]}-AABAAxUKz3U0KToap5s6VzigOhEHjRgPQgfSkCT3aFgHDoQAD_zWacmgVyX1fMTeb_4jdLlW_iMItLqTYrXYXA5IzDw`
  cmsg = Buffer.concat(cmsg)
  console.log("cmsg_string ------------------->",cmsg.toString())
  console.log("creating serialized message (controller):\n",cmsg.toString(),'\n')
  // console.log('SERIALIZED MESSAGE GENERATED BY CONTROLLER IS : ', cmsg.toString())
  assert.deepStrictEqual(cmsg, Buffer.from(cmsg_string, 'binary'))

  //#     # create own Coe Kever in  Coe's Kevery
  console.log("creating own controller Kever in  controller 's Kevery")
  // console.log("CONTROLLER'S OWN KEY VERIFIER : ", coeKevery.kevers)
  // console.log("\n\n SENDING COPY OF LOGS TO DATABASE :")
  coeKevery.processOne(cmsg)      // # send copy of cmsg1
  console.log("PROCESS ONE SUCCESSFULLY CALLED")
  let coeKever = await coeKevery.kevers[coepre]
  console.log("coeKever :", coeKever.prefixer.qb64())
  assert.deepStrictEqual(coeKever.prefixer.qb64(), coepre)
//   // console.log("CONTROLLER'S DATA SUCCESSFULLY VERIFIED")


  let val_ = valSigners[vesn].verfer()
  let val1_ = valSigners[vesn + 1].verfer()

  
  //# Val Event 0  Inception Transferable (by Validator)
  // console.log("CREATING INSCEPTION EVENT 0 BY VALIDATOR :")
  let valSerder = Trait_instance.incept([val_.qb64()], derivationCodes.oneCharCode.Blake3_256
    , Versionage, Serials.json, null,
    new Nexter(null, null, [val1_.qb64()]).qb64())

  let ked_ = valSerder.ked()
  // console.log("VALERDER KEd IS :", val1_.qb64() , val_.qb64())
  valSerder.set_ked(ked_)
  console.log("valSerder.ked() ======================>",valSerder.ked())
  let valpre = valSerder.ked()['pre']

  assert.deepStrictEqual(parseInt(valSerder.ked()["sn"], 16), 0)
  assert.deepStrictEqual(vsn, 0)
  assert.deepStrictEqual(valpre, 'EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAY')
  val_event_digs.push(valSerder.dig())





  // //         create sig counter
  // //         counter = SigCounter()  # default is count = 1
  // //         sign serialization
    // console.log("SIGNING SERIALIZATION:")
  siger = await valSigners[vesn].sign(valSerder.raw(), 0) // # return Siger if index
  console.log("SIGNATURE WITH VERFER PROPERTY:", siger.qb64b())
  console.log("SERIALIZATION SUCCESSFULLY SIGNED")
  // //      create serialized message


  let vmsg = [valSerder.raw(), counter.qb64b(), siger.qb64b()]
  vmsg = Buffer.concat(vmsg)
  console.log("Creating Val Event 0  Inception Transferable (by Validator)\n\n",vmsg.toString())
  console.log('VMSG BEFORE VALS KEVERY IS =========', vmsg.toString())
  console.log("valKevery.kevers[valpre] =============>",valKevery.kevers[valpre])
  //   # create own Val Kever in  Val's Kevery
  // console.log(" ######### PROCESS ONE CALLING  ##############################2")
  try { valKevery.processOne(vmsg) } catch (e) {
    console.log("ERROR IS ------------->", e)
  }
  // // // // //   //  send copy of vmsg
  console.log("valpre ===================>", valpre)
  let valKever = await valKevery.kevers[valpre]
  // let qb64b = await valKever.diger.qb64b()
  // let coe_qqb64 = coeKever.diger.qb64b()
  console.log("Hi =========================>", (valKever.prefixer.qb64()).toString())
  // console.log('VALEKEVERY. KEVERS IS : ========', valKever)
  assert.deepStrictEqual(valKever.prefixer.qb64(), valpre)

  console.log("simulating sending of coe's inception message to val")
  //     # simulate sending of coe's inception message to val
  console.log("SIMULATING COE'S INCEPTION MESSAGE TO VAL=================")
  valKevery.processAll(cmsg)  //# make copy of msg3
    console.log("valKevery.kevers() ====================>")
    // assert coepre in valKevery.kevers         // # creates Kever for coe in val's .kevers

 // console.log("valKever.lastEst.dig ====================>", qb64b.toString())
 // valKever.lastEst.dig = qb64b.toString()

  // console.log("valKever.lastEst.dig ====================>", valKever)
  //  # create receipt of coe's inception
  // # create seal of val's last est event
  // console.log('CREATING SEAL FOR COE LAST EST EVENT')
  // console.log("valKever.lastEst.dig ====================>", valpre)
  //  console.log("valpre ===================>",valKevery.kevers)
  // console.log(" Validator will create receipt of coe's inception  :")
  let SealEvent = {pre : "",dig:""}
  SealEvent.pre = valpre
  SealEvent.dig = valKever.lastEst.dig   ///valKever.lastEst.dig
  let seal = SealEvent
  let coeK = await valKevery.kevers[coepre] // # lookup coeKever from val's .kevers
  // console.log("coeK ===================>",valKevery)
//   // // // // //   //  # create validator receipt
  let reserder = Trait_instance.chit(coeK.prefixer.qb64(),
    coeK.sn,
    coeK.diger.qb64(),
    seal, Versionage, Serials.json)

  ked = reserder.ked()
  reserder.set_ked(ked)
  // console.log("reserder =====================+>",'\n\n\n')
  // console.log("reserder RAW =====================+>",(reserder.raw()).toString())
  console.log(" validator will ssign coe's event not receipt ")
       //  # sign coe's event not receipt
      //  # look up event to sign from val's kever for coe
   console.log("snkey(coepre, csn)",snkey(coepre, csn))
   //   console.log("look up event to sign from val's kever for coe")
  let coeIcpDig = valKevery.logger.getKeLast(snkey(coepre, csn))
  console.log("DATA", coeIcpDig.toString())
  console.log("coepre ===============>", coepre)
    //   // let coeIcpDig = Buffer.from(data, 'binary')
  // // console.log('valKevery.logger ====================>',dgkey(coepre,coeIcpDig).toString())
  console.log("coeIcpDig =================================>",coeK.diger)
  assert.deepStrictEqual(coeK.diger.qb64(),coeIcpDig.toString())
  assert.deepStrictEqual(coeK.diger.qb64(), 'EmyxWXl_tNYzRGGjwA2IOi2yBBG_cIniU1JVdB6nHFgc')  // Val ke key hai ye
  let coeIcpRaw = valKevery.logger.getEvt(dgkey(coepre, coeIcpDig))
  console.log("coeIcpRaw ==============>", coeIcpRaw.toString())
  let buf_ = `{"vs":"KERI10JSON0000fb_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","wits":[],"cnfg":[]}`
  console.log("look up event to sign from val's kever for coe :",coeIcpRaw.toString())


  let raw = Buffer.from(buf_, 'binary')
  assert.deepStrictEqual(coeIcpRaw, raw)
  // // //   // #     counter = SigCounter(count=1)
  counter = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64, null, 1)
  // console.log("COUNTER :", counter)
  assert.deepStrictEqual(counter.qb64(), '-AAB')
  // // #     assert counter.qb64 == '-AAB'
  siger = await valSigners[vesn].sign(coeIcpRaw, 0)      //# return Siger if index
  assert.deepStrictEqual(siger.qb64(), 'AAez7HD-dtLmHuG3M1nlodjPodCNVK7QPtlSzUlCyJsl3UuHnt39sVxqYRRW4mjkMMyTw_FvDVsDA5fplDM58kAw')




// //   // // // // // // // //   // //       // #     # process own Val receipt in Val's Kevery so have copy in own log

  let rmsg = [Buffer.from(reserder.raw(), 'binary'), Buffer.from(counter.qb64b(), 'binary'), Buffer.from(siger.qb64b(), 'binary')]

  rmsg = Buffer.concat(rmsg)
    // console.log("rmsg ================>",rmsg.toString())
  let vmsg_ = `{"vs":"KERI10JSON00010c_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","ilk":"vrc","sn":"0","dig":"EmyxWXl_tNYzRGGjwA2IOi2yBBG_cIniU1JVdB6nHFgc","seal":{"pre":"EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAY","dig":"EAdmmM5ZwZF5sJFJN5jMkh5WdS-79c3oAtonBMDBChg8"}}-AABAAez7HD-dtLmHuG3M1nlodjPodCNVK7QPtlSzUlCyJsl3UuHnt39sVxqYRRW4mjkMMyTw_FvDVsDA5fplDM58kAw`
  vmsg_ = Buffer.from(vmsg_, 'binary')
  // console.log("\n # Validator will  process own Val receipt in Val's Kevery so have copy in own log\n\n", rmsg.toString(),'\n')
  assert.deepStrictEqual(rmsg, vmsg_)

  valKevery.processOne(rmsg)  //# process copy of rmsg4

//   // // // #     # attach reciept message to existing message with val's incept message
  
  vmsg = Buffer.concat([vmsg, rmsg])
  // console.log("vmsg =======>", vmsg.toString())
  let vmsg1_ = `{"vs":"KERI10JSON0000fb_","pre":"EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAY","sn":"0","ilk":"icp","sith":"1","keys":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"nxt":"E29akD_tuTrdFXNHBQWdo6qPVXsoOu8K2A4LssoCunwc","toad":"0","wits":[],"cnfg":[]}-AABAA23aEckS_DxKOrfr4NOzk_KlLtZ_kCrUkSpgf9Y7ulvZIkayvRRGpi4j0CUBGkHJosXiUrKscJR2IRumoTdQrCA{"vs":"KERI10JSON00010c_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","ilk":"vrc","sn":"0","dig":"EmyxWXl_tNYzRGGjwA2IOi2yBBG_cIniU1JVdB6nHFgc","seal":{"pre":"EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAY","dig":"EAdmmM5ZwZF5sJFJN5jMkh5WdS-79c3oAtonBMDBChg8"}}-AABAAez7HD-dtLmHuG3M1nlodjPodCNVK7QPtlSzUlCyJsl3UuHnt39sVxqYRRW4mjkMMyTw_FvDVsDA5fplDM58kAw`
  vmsg1_ = Buffer.from(vmsg1_, 'binary')
  // console.log(`Validator will attach reciept message to existing message with val's incept message\n`,vmsg.toString(),'\n')
  assert.deepStrictEqual(vmsg, vmsg1_)

// //   // // // // // #    

  console.log(" #Validator will  Simulate and send to controller of val's incept + validator's receipt of controller's inception message")
  try { coeKevery.processAll(vmsg) } catch (e) {
    console.log("ERROR :", e)
  }
  // coeKever.lastEst.dig = 'EmyxWXl_tNYzRGGjwA2IOi2yBBG_cIniU1JVdB6nHFgc'
  
  // coeKever.lastEst.dig = coe_qqb64.toString() 
  console.log("valKever.prefixer.qb64b() ================>" )
  // console.log("coKever ========================>",coeKever)
  // // //   // #  coe process val's incept and receipt


// //   // // //   // #     # check if val Kever in coe's .kevers
// //   // // //   // #     assert valpre in coeKevery.kevers
// //   // // //   // #     #  check if receipt from val in receipt database

    let dgkey_ = dgkey(coeKever.prefixer.qb64(), coeKever.diger.qb64())
    let result_ =  coeKevery.logger.getVrcs(dgkey_)
    // console.log("################### valKever.prefixer.qb64() ####################",valKever.diger)
    // console.log("valKever.prefixer.qb64b() ================>",valKever)
    let val_sig = [valKever.prefixer.qb64b(),Buffer.from(valKever.lastEst.dig,'binary'),siger.qb64b()]
    val_sig  = Buffer.concat(val_sig)
    // console.log("result_ -=========================>", result_[0].toString())
    // console.log("val_sig -=========================>", val_sig.toString())
    assert.deepStrictEqual(result_[0],val_sig)
    assert.deepStrictEqual(result_[0].toString(), `EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAYEAdmmM5ZwZF5sJFJN5jMkh5WdS-79c3oAtonBMDBChg8AAez7HD-dtLmHuG3M1nlodjPodCNVK7QPtlSzUlCyJsl3UuHnt39sVxqYRRW4mjkMMyTw_FvDVsDA5fplDM58kAw`)
    // #     # create receipt to escrow use invalid dig and sn so not in coe's db
    console.log("# create receipt to escrow use invalid dig and sn so not in coe's db")
    let fake = reserder.dig()  //# some other dig

    reserder =  Trait_instance.chit(coeK.prefixer.qb64(),
      10,
      fake,
      seal, Versionage, Serials.json)

    ked = reserder.ked()
    reserder.set_ked(ked)

  // // // //   // #     # sign event not receipt
  // // // //   // #     counter = SigCounter(count=1)
    siger =  await valSigners[vesn].sign(coeIcpRaw, 0)       //# return Siger if index
  // // // // //   // #     # create message
      // console.log("")
    vmsg = [Buffer.from(reserder.raw(), 'binary'), Buffer.from(counter.qb64b(), 'binary'), Buffer.from(siger.qb64b(), 'binary')]
    vmsg = Buffer.concat(vmsg)
    console.log("\n # create message\n\n", vmsg.toString())

      vmsg1 = `{"vs":"KERI10JSON00010c_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","ilk":"vrc","sn":"a","dig":"E8NHnmjzoG9ITC40QdhLqGhiB3V50FaV3wzaTMI7SHmA","seal":{"pre":"EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAY","dig":"EAdmmM5ZwZF5sJFJN5jMkh5WdS-79c3oAtonBMDBChg8"}}-AABAAez7HD-dtLmHuG3M1nlodjPodCNVK7QPtlSzUlCyJsl3UuHnt39sVxqYRRW4mjkMMyTw_FvDVsDA5fplDM58kAw`
      vmsg1 = Buffer.from(vmsg1,'binary')

      assert.deepStrictEqual(vmsg,vmsg1)

  // //     coeKever.lastEst.dig = coe_qqb64.toString() 
    // console.log("coKever ========================>")
    console.log("controller process the escrow receipt from val")
   coeKevery.processAll(vmsg)       //#  coe process the escrow receipt from val
         console.log("coKever ========================>")
    // #     #  check if in escrow database
    let get_Vres =  coeKevery.logger.getVres(dgkey(coeKever.prefixer.qb64(),fake))

   get_Vres = Buffer.from(get_Vres[0],'binary')

//   //  console.log("comparable value =  ")
//   //  console.log("\n\n\nget_Vres =====================> :",get_Vres.toString())
  assert.deepStrictEqual(get_Vres,Buffer.from((valKever.prefixer.qb64b() +valKever.diger.qb64b() +siger.qb64b()),'binary'))
//   // // #     assert bytes(result[0]) == (valKever.prefixer.qb64b +
//   // // #                                 valKever.diger.qb64b +
//   // // #                                 siger.qb64b)


  console.log("Send receipt from controller to validator ")
  console.log("\ncreate receipt of validator's inception")
  // console.log("\ncreate seal of coe's last est event")
  // // // // //   // #     # Send receipt from coe to val
  // // // // //   // #     # create receipt of val's inception
  // // // // //   // #     # create seal of coe's last est event
    SealEvent.pre =coepre
    SealEvent.dig = coeKever.lastEst.dig
         seal = SealEvent
        let valK = await coeKevery.kevers[valpre]  //# lookup valKever from coe's .kevers
  // // // //   // #     # create validator receipt

  console.log("\ncreating validator receipt")
    reserder =  Trait_instance.chit(valK.prefixer.qb64(),
    valK.sn,
    valK.diger.qb64(),
    seal, Versionage, Serials.json)
  // // 
  ked = reserder.ked()
  reserder.set_ked(ked)

  // // // // // //       // # sign vals's event not receipt
  // // // // // //   // #     # look up event to sign from coe's kever for val
  console.log("\nsigning vals's event not receipt")
  console.log("saving receipt in controller's own db for further use")
  console.log("\nlook up event to sign from controller's kever for val")
    // console.log("valIcpDig:",coeKevery.logger.getKes(snkey(valpre, vsn)))
    // console.log("valIcpDig :",(valK.diger.qb64b()).toString())
    let    valIcpDig = coeKevery.logger.getKeLast(snkey(valpre, vsn))
    console.log("valIcpDig[0]:",valIcpDig.toString())
    console.log("valIcpDig[1]:",(valK.diger.qb64b().toString()))
    valIcpDig = Buffer.from(valIcpDig,'binary')
    assert.deepStrictEqual(valIcpDig,valK.diger.qb64b())
    // console.log("valK.diger.qb64b() =====================>",(valK.diger.qb64b()).toString())
    assert.deepStrictEqual(valK.diger.qb64b(),Buffer.from('EAdmmM5ZwZF5sJFJN5jMkh5WdS-79c3oAtonBMDBChg8','binary'))


   let valIcpRaw = Buffer.from(coeKevery.logger.getEvt(dgkey(valpre, valIcpDig)),'binary')
    // console.log("valIcpRaw ===================>")
    let calIcpRaw_ = Buffer.from('{"vs":"KERI10JSON0000fb_","pre":"EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAY","sn":"0","ilk":"icp","sith":"1","keys":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"nxt":"E29akD_tuTrdFXNHBQWdo6qPVXsoOu8K2A4LssoCunwc","toad":"0","wits":[],"cnfg":[]}','binary')

  assert.deepStrictEqual(valIcpRaw,calIcpRaw_)
  // //   // #     counter = SigCounter(count=1)
    assert.deepStrictEqual(counter.qb64() , '-AAB')
  // //   // #     assert counter.qb64 == '-AAB'
         siger = await coeSigners[vesn].sign(valIcpRaw, 0)    // # return Siger if index
         assert.deepStrictEqual(siger.qb64(),'AAPJrY-fBD2FkQJ_p2m9w_sapqM2xB6uLuhqOftFVcS04QZgKQeXIZxeLHUUtH9ulc0-5Rcipr-4z1UVTzsQXiDg')
    // #     assert siger.qb64 == 'AAWsB5GblCXs43fNPPGqAlx5FWyEzdBSRb9wGqwwDen3Qq4yxaXVmEn9dZdK3Cq6l5Iq6CHxWiKCoUR5A3kG1LBg'

    // #     # create receipt message

            cmsg = [Buffer.from(reserder.raw(),'binary'),
            Buffer.from(counter.qb64b(),'binary'),
            Buffer.from(siger.qb64b(),'binary')]
            cmsg = Buffer.concat(cmsg)
      // console.log("cmsg",cmsg.toString())
      let cmsg_ = `{"vs":"KERI10JSON00010c_","pre":"EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAY","ilk":"vrc","sn":"0","dig":"EAdmmM5ZwZF5sJFJN5jMkh5WdS-79c3oAtonBMDBChg8","seal":{"pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","dig":"EmyxWXl_tNYzRGGjwA2IOi2yBBG_cIniU1JVdB6nHFgc"}}-AABAAPJrY-fBD2FkQJ_p2m9w_sapqM2xB6uLuhqOftFVcS04QZgKQeXIZxeLHUUtH9ulc0-5Rcipr-4z1UVTzsQXiDg`
            assert.deepStrictEqual(cmsg,Buffer.from(cmsg_,'binary'))
 
console.log("\n create receipt message \n",cmsg_)
  //   // #     # coe process own receipt in own Kevery so have copy in own log
  console.log("\ncoe process own receipt in own Kevery so have copy in own log")
      await  coeKevery.processOne(cmsg)   //# make copy

  // //  # Simulate send to val of coe's receipt of val's inception message
  console.log("Controller is Simulating and sending to validator of controller's receipt of validator's inception message")
     valKevery.processAll(cmsg)      //#  coe process val's incept and receipt

  // //  #  check if receipt from coe in val's receipt database
    console.log("validator is checkig  if receipt from controller in validator's receipt database")
   result = valKevery.logger.getVrcs(dgkey(valKever.prefixer.qb64(),valKever.diger.qb64()))
  

  // console.log("result[0]=======================>")
  assert.deepStrictEqual(result[0],Buffer.from(coeKever.prefixer.qb64b() +coeKever.diger.qb64b()+siger.qb64b(),'binary'))
  assert.deepStrictEqual(result[0].toString(),'EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3EEmyxWXl_tNYzRGGjwA2IOi2yBBG_cIniU1JVdB6nHFgcAAPJrY-fBD2FkQJ_p2m9w_sapqM2xB6uLuhqOftFVcS04QZgKQeXIZxeLHUUtH9ulc0-5Rcipr-4z1UVTzsQXiDg')

  // // // #     # Coe RotationTransferable
  console.log("Coe Rotation Transferable")
       csn += 1
        cesn += 1 
       assert.equal(csn,cesn)
      //  console.log("cesn ================>",cesn)
    let  coesigner0_ = coeSigners[cesn].verfer()



       coeSerder =  Trait_instance.rotate(coeKever.prefixer.qb64(),
       [coesigner0_.qb64()],coeKever.diger.qb64(),
       csn, Versionage, Serials.json,null,
       new Nexter(null, null, [coesigner0_.qb64()]).qb64(),
       )
 
     ked = coeSerder.ked()
     coeSerder.set_ked(ked)
     counter = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64)
     coe_event_digs.push(coeSerder.dig())
     siger = await coeSigners[cesn].sign(coeSerder.raw(), 0)


  // #     #  create serialized message

   cmsg = [coeSerder.raw(), counter.qb64b(), siger.qb64b()]
   cmsg = Buffer.concat(cmsg)
    // console.log("cmsg ==============+>",cmsg.toString()  )
      cmsg_  = `{"vs":"KERI10JSON00013a_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","sn":"1","ilk":"rot","dig":"EmyxWXl_tNYzRGGjwA2IOi2yBBG_cIniU1JVdB6nHFgc","sith":"1","keys":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"nxt":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","cuts":[],"adds":[],"data":[]}-AABAAnhFQiHG-5_cl9pSSX-eeSh8XEel8UghWUMdjfgtbAgG9m04SoGIOsjgmc84jM2Lyf-t4h0Do_f20c7MHnXSTBA`
    assert.deepStrictEqual(cmsg.toString(),cmsg_)

    console.log("creating serialized message\n\n",cmsg_)
  // #     # update coe's key event verifier state
  console.log(" updating controller's key event verifier state")
 await     coeKevery.processOne(cmsg) // # make copy
 console.log(" verify controller's copy of coe's event stream is updated")
  // #     # verify coe's copy of coe's event stream is updated
  assert.equal(coeKever.sn , csn)        // These value should not be same 
  assert.equal(coeKever.diger.qb64() , coeSerder.dig())      // these two digest should not be same 


  // console.log('BEFORE PROCESSALL ==========>')
  // // // #     # simulate send message from coe to val
  console.log("simulate send message from controller to validator ")
       valKevery.processAll(cmsg)

      //  console.log('AFTER PROCESSALL ==========>',coeK.sn)
         // #     # verify val's copy of coe's event stream is updated
         console.log("verify validator's copy of controller's event stream is updated")
       assert.deepStrictEqual(coeK.sn , csn)
       assert.deepStrictEqual(coeK.diger.qb64() , coeSerder.dig())



  // #     # create receipt of coe's rotation
  // #     # create seal of val's last est event
  SealEvent.pre =valpre
  SealEvent.dig = valKever.lastEst.dig
       seal = SealEvent
console.log("# create receipt of controller's rotation")
console.log("# create validator receipt")
  // #     # create validator receipt

   reserder= Trait_instance.chit(coeK.prefixer.qb64(),
  coeK.sn,
  coeK.diger.qb64(),
  seal, Versionage, Serials.json)

  ked = reserder.ked()
  reserder.set_ked(ked)

  // console.log("reserder5 ===================>",reserder)
  // #     # sign coe's event not receipt
  // #     # look up event to sign from val's kever for coe
  console.log("sign controller's event not receipt")
  console.log("look up event to sign from validator's kever for controller")
      let coeRotDig = valKevery.logger.getKeLast(snkey(coepre,csn))
      assert.deepStrictEqual(coeRotDig  ,coeK.diger.qb64b())
      // console.log("coeK.diger.qb64b() ===============>",(coeK.diger.qb64b()).toString())
      assert.deepStrictEqual(coeRotDig  ,Buffer.from('Eu4ONQk4BmAW9hMyQlh3kq1icF4pkG8qOpjPsAv5vtFs','binary'))
     let coeRotRaw = valKevery.logger.getEvt(dgkey(coepre,coeRotDig))
    //  console.log("coeRotRaw ---------------------->",coeRotRaw.toString())

     let coeRotRaw_ = `{"vs":"KERI10JSON00013a_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","sn":"1","ilk":"rot","dig":"EmyxWXl_tNYzRGGjwA2IOi2yBBG_cIniU1JVdB6nHFgc","sith":"1","keys":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"nxt":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","cuts":[],"adds":[],"data":[]}`
 assert.deepStrictEqual(coeRotRaw.toString(),coeRotRaw_)
// let  counter5 = new Sigcounter(null, null, null, null, derivationCodes.SigCntCodex.Base64, null, 1)
      siger = await  valSigners[vesn].sign(coeRotRaw, 0)      // # return Siger if index

      //  console.log("siger ==================>",siger.qb64())
      assert.deepStrictEqual(siger.qb64(),`AAuKYFfqyOtLD0RmiMFTtCK_RNtr0P2LH-64lTjAmMBQPvJn-sAsjzKd9IeWfHv2YAeGwkxrkbYxhCu5QD8COgDg`)
      
  // #     # val create receipt message
  console.log("validator create receipt message\n\n")
  vmsg = [reserder.raw(), counter.qb64b(), siger.qb64b()]
// console.log("vmsg ====================>",vmsg.toString())
 vmsg = Buffer.concat(vmsg)
//  console.log("vmsg ====================>",vmsg.toString())  

   vmsg_ = `{"vs":"KERI10JSON00010c_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","ilk":"vrc","sn":"1","dig":"Eu4ONQk4BmAW9hMyQlh3kq1icF4pkG8qOpjPsAv5vtFs","seal":{"pre":"EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAY","dig":"EAdmmM5ZwZF5sJFJN5jMkh5WdS-79c3oAtonBMDBChg8"}}-AABAAuKYFfqyOtLD0RmiMFTtCK_RNtr0P2LH-64lTjAmMBQPvJn-sAsjzKd9IeWfHv2YAeGwkxrkbYxhCu5QD8COgDg`
 assert.deepStrictEqual(vmsg , Buffer.from(vmsg_,'binary'))

  // #     # val process own receipt in own kevery so have copy in own log
  console.log("# validator process own receipt in own kevery so have copy in own log")
       valKevery.processOne(vmsg) // # make copy
      //  console.log("vmsg ====================>",vmsg.toString())
  // #     # Simulate send to coe of val's receipt of coe's rotation message
  console.log("\n# validator Simulate and  send to controller of validator's receipt of controller's rotation message")
       coeKevery.processAll(vmsg)  //  #  coe process val's incept and receipt

  // #     #  check if receipt from val in receipt database
         result = coeKevery.logger.getVrcs(dgkey(coeKever.prefixer.qb64(),coeKever.diger.qb64()))
         assert.deepStrictEqual(result[0].toString(),(valKever.prefixer.qb64b() +valKever.diger.qb64b() +siger.qb64b()))
        //  console.log("result[0] ===============>",result[0].toString())

         assert.deepStrictEqual(result[0].toString(),`EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAYEAdmmM5ZwZF5sJFJN5jMkh5WdS-79c3oAtonBMDBChg8AAuKYFfqyOtLD0RmiMFTtCK_RNtr0P2LH-64lTjAmMBQPvJn-sAsjzKd9IeWfHv2YAeGwkxrkbYxhCu5QD8COgDg`)

  // #     # Next Event Coe Interaction
  console.log("\n# Next Event controller Interaction")
       csn += 1   //#  do not increment esn
       assert.equal(csn , 2)
       assert.equal(cesn , 1)
     
     
     
        coeSerder = Trait_instance.interact(coeKever.prefixer.qb64(),coeKever.diger.qb64(), csn
       , Versionage, Serials.json)
   
      ked = coeSerder.ked()
    //  console.log("COSERDER KED IS :", ked)
     coeSerder.set_ked(ked)

     coe_event_digs.push(coeSerder.dig())
  // #     assert csn == 2
  // #     assert cesn == 1
  // #     coeSerder = interact(pre=coeKever.prefixer.qb64,
  // #                           dig=coeKever.diger.qb64,
  // #                           sn=csn)
  // #     coe_event_digs.append(coeSerder.dig)
  // #     # create sig counter
  // #     counter = SigCounter()  # default is count = 1
  // #     # sign serialization
       siger = await coeSigners[cesn].sign(coeSerder.raw(),0)

  // #     # create msg
// console.log("OLD CMSG = ",cmsg.toString())
 cmsg = [coeSerder.raw(), counter.qb64b(), siger.qb64b()]
cmsg = Buffer.concat(cmsg)
// console.log("NEW CMSG = ",cmsg.toString())
cmsg_ = `{"vs":"KERI10JSON0000a3_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","sn":"2","ilk":"ixn","dig":"Eu4ONQk4BmAW9hMyQlh3kq1icF4pkG8qOpjPsAv5vtFs","data":[]}-AABAAEEI5iKVv3xufP14oKpggTsbZkiFAPfLmLOG9-N6NuXiEm-ftIXEJMoaUqdrBgN8It43AmMks6RldGtHECY0KBQ`
assert,deepStrictEqual(cmsg , Buffer.from(cmsg_,'binary'))
console.log("\n# create msg :\n",cmsg_)


  // #     # update coe's key event verifier state
  console.log("# update controller's key event verifier state")
       coeKevery.processOne(cmsg) // # make copy
       console.log(" # verify cntroller's copy of controller's event stream is updated")
  // #     # verify coe's copy of coe's event stream is updated
  assert.deepStrictEqual(coeKever.sn , csn)
  assert.deepStrictEqual(coeKever.diger.qb64() , coeSerder.dig())
  // #     assert coeKever.sn == csn
  // #     assert coeKever.diger.qb64 == coeSerder.dig

  // #     # simulate send message from coe to val
  console.log(" # simulate send message from controller to validator")
       valKevery.processAll(cmsg)



  // #     # verify val's copy of coe's event stream is updated
  console.log(" # verify validator's copy of controller's event stream is updated")
  assert.deepStrictEqual(coeK.sn , csn)
  assert.deepStrictEqual(coeK.diger.qb64() , coeSerder.dig())


  // #     # create receipt of coe's interaction
  // #     # create seal of val's last est event
  console.log(" # create receipt of controller's interaction")
  console.log(" # create seal of validator's last est event")
  SealEvent.pre = valpre
  SealEvent.dig = valKever.lastEst.dig   ///valKever.lastEst.dig
   seal = SealEvent
  // #     seal = SealEvent(pre=valpre, dig=valKever.lastEst.dig)
  // #     # create validator receipt

   reserder = Trait_instance.chit(coeK.prefixer.qb64(),
  coeK.sn,
  coeK.diger.qb64(),
  seal, Versionage, Serials.json)

ked = reserder.ked()
reserder.set_ked(ked)


  // #     reserder = chit(pre=coeK.prefixer.qb64,
  // #                     sn=coeK.sn,
  // #                     dig=coeK.diger.qb64,
  // #                     seal=seal)

  // #     # sign coe's event not receipt
  // #     # look up event to sign from val's kever for coe
  console.log(" # sign controller's event not receipt")
  console.log(" # look up event to sign from validator's kever for controller\n")
let   coeIxnDig = valKevery.logger.getKeLast(snkey(coepre, csn))
assert.deepStrictEqual(coeIxnDig,coeK.diger.qb64b())
// console.log("coeIxnDig -================>",coeIxnDig.toString())
assert.deepStrictEqual(coeIxnDig.toString(), `EkpnsM8T3VcBsiGxSN7KHKc2-e-yrRvgG1DhOTY82PNs`)
let coeIxnRaw = valKevery.logger.getEvt(dgkey(coepre,coeIxnDig))
// console.log("coeIxnRaw =================>",coeIxnRaw.toString())

let coeIxnRaw_ = `{"vs":"KERI10JSON0000a3_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","sn":"2","ilk":"ixn","dig":"Eu4ONQk4BmAW9hMyQlh3kq1icF4pkG8qOpjPsAv5vtFs","data":[]}`
    assert.deepStrictEqual(Buffer.from(coeIxnRaw_,'binary'),coeIxnRaw)

  // #     counter = SigCounter(count=1)
       siger = await valSigners[vesn].sign(coeIxnRaw, 0)  // # return Siger if index
      //  console.log("siger.qb64 ==================>",siger.qb64())
       assert.deepStrictEqual(siger.qb64(),`AAyalO3CBhIrv5ywmQx3V82RxwvN94UjZxIucYP0YR_XAvfraYvus7XpmFXzTfvVDBVnJ7XfZD4slygn0H6FTUAg`)


  // #     # create receipt message
  
  vmsg = [reserder.raw(), counter.qb64b(), siger.qb64b()]
// console.log("vmsg ====================>",vmsg.toString())
 vmsg = Buffer.concat(vmsg)
  // console.log("vmsg ===============>",vmsg.toString())
  vmsg_ = `{"vs":"KERI10JSON00010c_","pre":"EN7nOioHAZlAuQgEs77Zz1gAzVsGwWNwpwUXxqhDWt3E","ilk":"vrc","sn":"2","dig":"EkpnsM8T3VcBsiGxSN7KHKc2-e-yrRvgG1DhOTY82PNs","seal":{"pre":"EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAY","dig":"EAdmmM5ZwZF5sJFJN5jMkh5WdS-79c3oAtonBMDBChg8"}}-AABAAyalO3CBhIrv5ywmQx3V82RxwvN94UjZxIucYP0YR_XAvfraYvus7XpmFXzTfvVDBVnJ7XfZD4slygn0H6FTUAg`

  console.log("  # create receipt message\n",vmsg_)
  Buffer.from(vmsg , Buffer.from(vmsg_,'binary'))

  // #     # val process own receipt in own kevery so have copy in own log

  console.log(" # validator process own receipt in own kevery so have copy in own log")
     valKevery.processOne(vmsg)  //# make copy

  // #     # Simulate send to coe of val's receipt of coe's rotation message
  console.log(" # Simulate send to controller of validator's receipt of controller's rotation message")
       coeKevery.processAll(vmsg)  // #  coe process val's incept and receipt
       console.log("#  check if receipt from validator in receipt database")
  // #     #  check if receipt from val in receipt database
       result = coeKevery.logger.getVrcs(dgkey(coeKever.prefixer.qb64(),coeKever.diger.qb64()))
      //  console.log("execution finished =======================>",result[0].toString())
       assert.deepStrictEqual(result[0],Buffer.from(valKever.prefixer.qb64b() +valKever.diger.qb64b()+siger.qb64b(),'binary'))
       assert.deepStrictEqual(result[0].toString(),`EmWUcTv3revddO0RML3XhrNxGjkcVHzKJFKejyRnANAYEAdmmM5ZwZF5sJFJN5jMkh5WdS-79c3oAtonBMDBChg8AAyalO3CBhIrv5ywmQx3V82RxwvN94UjZxIucYP0YR_XAvfraYvus7XpmFXzTfvVDBVnJ7XfZD4slygn0H6FTUAg`)


  // #     #  verify final coe event state
  console.log("#  verify final cntroller event state")
  assert.deepStrictEqual(coeKever.verfers[0].qb64() , coeSigners[cesn].verfer().qb64())
  assert.deepStrictEqual(coeKever.sn , coeK.sn)
  assert.deepStrictEqual(coeK.sn , csn)


  // #     db_digs = [bytes(v).decode("utf-8") for v in coeKever.logger.getKelIter(coepre)]
  // #     assert len(db_digs) == len(coe_event_digs) == csn+1
  // #     assert db_digs == coe_event_digs == ['EixO2SBNow3tYDfYX6NRt1O9ZSMx2IsBeWkh8YJRp5VI',
  // #                                          'E7MC1Sr7igW4JEDdvZu_HtmNoyBn4_Th-TcfKwwFBYR4',
  // #                                          'Ec9ivQTiqBXBhx4d2HCA7qfUksJyB6sKSHz5cHufFiyo']


  // #     db_digs = [bytes(v).decode("utf-8") for v in valKever.logger.getKelIter(coepre)]
  // #     assert len(db_digs) == len(coe_event_digs) == csn+1
  // #     assert db_digs == coe_event_digs == ['EixO2SBNow3tYDfYX6NRt1O9ZSMx2IsBeWkh8YJRp5VI',
  // #                                          'E7MC1Sr7igW4JEDdvZu_HtmNoyBn4_Th-TcfKwwFBYR4',
  // #                                          'Ec9ivQTiqBXBhx4d2HCA7qfUksJyB6sKSHz5cHufFiyo']


  // #     #  verify final val event state
  console.log("#  verify final val event state")
  assert.deepStrictEqual(valKever.verfers[0].qb64() , valSigners[vesn].verfer().qb64())
  assert.deepStrictEqual(valKever.sn , valK.sn)
  // console.log('valKever.sn =================>',valKever)
  // assert.deepStrictEqual(valKever.sn , vsn)
  // #     assert valKever.verfers[0].qb64 == valSigners[vesn].verfer.qb64
  // #     assert valKever.sn == valK.sn == vsn

  // #     db_digs = [bytes(v).decode("utf-8") for v in valKever.logger.getKelIter(valpre)]
  // #     assert len(db_digs) == len(val_event_digs) == vsn+1
  // #     assert db_digs == val_event_digs == ['E0CxRRD8SSBHZlSt-gblJ5_PL6JskFaaHsnSiAgX5vrA']

  // #     db_digs = [bytes(v).decode("utf-8") for v in coeKever.logger.getKelIter(valpre)]
  // #     assert len(db_digs) == len(val_event_digs) == vsn+1
  // #     assert db_digs == val_event_digs == ['E0CxRRD8SSBHZlSt-gblJ5_PL6JskFaaHsnSiAgX5vrA']

  // # assert not os.path.exists(valKevery.logger.path)
  // # assert not os.path.exists(coeKever.logger.path)


}
test_direct_mode()