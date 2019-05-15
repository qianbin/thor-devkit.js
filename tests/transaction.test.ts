import { expect } from 'chai'
import { cry, Transaction } from '../src'

// tslint:disable:quotemark
// tslint:disable:object-literal-key-quotes
// tslint:disable:max-line-length
// tslint:disable:trailing-comma

describe("transaction", () => {
    const body: Transaction.Body = {
        chainTag: 1,
        blockRef: '0x00000000aabbccdd',
        expiration: 32,
        clauses: [{
            to: '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
            value: 10000,
            data: '0x000000606060'
        }, {
            to: '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
            value: 20000,
            data: '0x000000606060'
        }],
        gasPriceCoef: 128,
        gas: 21000,
        dependsOn: null,
        nonce: 12345678,
    }
    const unsigned = new Transaction(body)
    const unsignedEncoded = Buffer.from('f8540184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec0', 'hex')

    it('unsigned', () => {
        const signingHash = cry.blake2b256(unsigned.encode())
        expect(signingHash.toString('hex')).equal('2a1c25ce0d66f45276a5f308b99bf410e2fc7d5b6ea37a49f2ab9f1da9446478')
        expect(unsigned.signingHash().toString('hex')).equal('2a1c25ce0d66f45276a5f308b99bf410e2fc7d5b6ea37a49f2ab9f1da9446478')

        expect(unsigned.id).equal(null)
        expect(unsigned.intrinsicGas).equal(37432)
        expect(new Transaction({ ...body, clauses: [] }).intrinsicGas).equal(21000)
        expect(new Transaction({
            ...body,
            clauses: [{
                to: null,
                value: 0,
                data: '0x'
            }]
        }).intrinsicGas).equal(53000)

        expect(unsigned.signature).equal(undefined)
        expect(unsigned.origin).equal(null)

        expect(unsigned.encode().toString('hex')).equal(unsignedEncoded.toString('hex'))
        expect(Transaction.decode(unsignedEncoded, true))
            .deep.equal(unsigned)
    })

    it('invalid body', () => {
        expect(() => { new Transaction({ ...body, chainTag: 256 }).encode() }).to.throw()
        expect(() => { new Transaction({ ...body, chainTag: -1 }).encode() }).to.throw()
        expect(() => { new Transaction({ ...body, chainTag: 1.1 }).encode() }).to.throw()

        expect(() => { new Transaction({ ...body, blockRef: '0x' }).encode() }).to.throw()
        expect(() => { new Transaction({ ...body, blockRef: '0x' + '0'.repeat(18) }).encode() }).to.throw()

        expect(() => { new Transaction({ ...body, expiration: 2 ** 32 }).encode() }).to.throw()
        expect(() => { new Transaction({ ...body, expiration: -1 }).encode() }).to.throw()
        expect(() => { new Transaction({ ...body, expiration: 1.1 }).encode() }).to.throw()

        expect(() => { new Transaction({ ...body, gasPriceCoef: 256 }).encode() }).to.throw()
        expect(() => { new Transaction({ ...body, gasPriceCoef: -1 }).encode() }).to.throw()
        expect(() => { new Transaction({ ...body, gasPriceCoef: 1.1 }).encode() }).to.throw()

        expect(() => { new Transaction({ ...body, gas: '0x10000000000000000' }).encode() }).to.throw()
        expect(() => { new Transaction({ ...body, nonce: '0x10000000000000000' }).encode() }).to.throw()
    })

    const signed = new Transaction(body)
    const signedEncoded = Buffer.from('f8970184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec0b841f76f3c91a834165872aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884193c3f313ff8effbb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00', 'hex')
    const privKey = Buffer.from('7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a', 'hex')
    signed.signature = cry.secp256k1.sign(cry.blake2b256(signed.encode()), privKey)
    const signer = cry.publicKeyToAddress(cry.secp256k1.derivePublicKey(privKey))

    it("signed", () => {
        expect(signed.signature!.toString('hex')).equal('f76f3c91a834165872aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884193c3f313ff8effbb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00')
        expect(signed.origin).equal('0x' + signer.toString('hex'))
        expect(signed.id).equal('0xda90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec')
        expect(signed.signingHash('0x' + signer.toString('hex')).toString('hex')).equal('da90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec')
    })

    it("encode decode", () => {
        expect(signed.encode().toString('hex')).equal(signedEncoded.toString('hex'))
        expect(Transaction.decode(signedEncoded)).deep.equal(signed)

        expect(() => Transaction.decode(unsignedEncoded)).to.throw()
        expect(() => Transaction.decode(signedEncoded, true)).to.throw()
    })

    const incorrectlySigned = new Transaction(body)
    incorrectlySigned.signature = Buffer.from([1, 2, 3])
    it('incorrectly signed', () => {
        expect(incorrectlySigned.origin).equal(null)
        expect(incorrectlySigned.id).equal(null)
    })


    const delegated = new Transaction({
        chainTag: 1,
        blockRef: '0x00000000aabbccdd',
        expiration: 32,
        clauses: [{
            to: '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
            value: 10000,
            data: '0x000000606060'
        }, {
            to: '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
            value: 20000,
            data: '0x000000606060'
        }],
        gasPriceCoef: 128,
        gas: 21000,
        dependsOn: null,
        nonce: 12345678,
        reserved: {
            features: 1
        }
    })

    it('features', () => {
        expect(unsigned.delegated).equal(false)
        expect(delegated.delegated).equal(true)

        const priv1 = cry.secp256k1.generatePrivateKey()
        const priv2 = cry.secp256k1.generatePrivateKey()
        const addr1 = cry.publicKeyToAddress(cry.secp256k1.derivePublicKey(priv1))
        const addr2 = cry.publicKeyToAddress(cry.secp256k1.derivePublicKey(priv2))

        const hash = delegated.signingHash()
        const dhash = delegated.signingHash('0x' + addr1.toString('hex'))

        const sig = Buffer.concat([
            cry.secp256k1.sign(hash, priv1),
            cry.secp256k1.sign(dhash, priv2)
        ])

        delegated.signature = sig

        expect(delegated.origin).equal('0x' + addr1.toString('hex'))
        expect(delegated.delegator).equal('0x' + addr2.toString('hex'))

        // from thor's test case
        const tx = Transaction.decode(Buffer.from('f8db81a484aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e20860000006060608180830334508083bc614ec101b882bad4d4401b1fb1c41d61727d7fd2aeb2bb3e65a27638a5326ca98404c0209ab159eaeb37f0ac75ed1ac44d92c3d17402d7d64b4c09664ae2698e1102448040c000f043fafeaf60343248a37e4f1d2743b4ab9116df6d627b4d8a874e4f48d3ae671c4e8d136eb87c544bea1763673a5f1762c2266364d1b22166d16e3872b5a9c700', 'hex'))
        expect(tx.signingHash().toString('hex')).equal('96c4cd08584994f337946f950eca5511abe15b152bc879bf47c2227901f9f2af')
        expect(tx.signingHash('0xd989829d88b0ed1b06edf5c50174ecfa64f14a64').toString('hex')).equal('956577b09b2a770d10ea129b26d916955df3606dc973da0043d6321b922fdef9')
        expect(tx.origin).equal('0xd989829d88b0ed1b06edf5c50174ecfa64f14a64')
        expect(tx.delegator).equal('0xd3ae78222beadb038203be21ed5ce7c9b1bff602')
    })
})
