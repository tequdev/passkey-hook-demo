import { readFileSync } from 'node:fs'
import { setInterval } from 'node:timers'
import { Wallet, Client, ECDSA, xahToDrops, SetHookFlags, calculateHookOn, Transaction, SubmittableTransaction, convertStringToHex, encode } from 'xahau'

const genesis = Wallet.fromSecret('snoPBrXtMeMyMHUVTgbuqAfg1SUTb', { algorithm: ECDSA.secp256k1 })

const client = new Client('ws://localhost:6006')

const generateWallet = async () => {
  return Wallet.generate()
}

const fundWallet = async (wallet: Wallet) => {
  await client.connect()
  const intervalId = setInterval(() => {
    client.request({ command: 'ledger_accept' as any })
  }, 500)
  await client.submitAndWait({
    TransactionType: 'Payment',
    Account: genesis.address,
    Amount: xahToDrops(1000),
    Destination: wallet.address,
  }, { wallet: genesis })
  clearInterval(intervalId)
  await client.disconnect()
}

const installHook = async (wallet: Wallet) => {
  await client.connect()
  const intervalId = setInterval(() => {
    client.request({ command: 'ledger_accept' as any })
  }, 500)
  console.log(JSON.stringify({
    TransactionType: 'SetHook',
    Account: wallet.address,
    Hooks: [
      {
        Hook: {
          CreateCode: readFileSync('contracts/index.wasm').toString('hex').toUpperCase(),
          Flags: SetHookFlags.hsfOverride,
          HookApiVersion: 0,
          HookNamespace: '00'.repeat(32),
          HookOn: calculateHookOn(['Invoke']),
        }
      }
    ]
  }, null, 2))
  await client.submitAndWait({
    TransactionType: 'SetHook',
    Account: wallet.address,
    Hooks: [
      {
        Hook: {
          CreateCode: readFileSync('contracts/index.wasm').toString('hex').toUpperCase(),
          Flags: SetHookFlags.hsfOverride,
          HookApiVersion: 0,
          HookNamespace: '00'.repeat(32),
          HookOn: calculateHookOn(['Invoke']),
        }
      }
    ]
  }, { wallet })
  clearInterval(intervalId)
  await client.disconnect()
}

type VerificationData = {
  signature: {
    r: Buffer
    s: Buffer
  }
  publicKey: {
    x: Buffer
    y: Buffer
  }
  authData: Buffer
  challengePtr: number
  challengeLen: number
}

const bufferToHex = (buffer: ArrayBuffer) => {
  return [...new Uint8Array(buffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("").toUpperCase();
}

const submitPasskeyTransaction = async (address: string, clientDataJSON: Buffer, verificationData: VerificationData) => {
  await client.connect()
  const intervalId = setInterval(() => {
    client.request({ command: 'ledger_accept' as any })
  }, 500)
  await client.submitAndWait({
    TransactionType: 'Invoke',
    Account: genesis.address,
    Destination: address,
    Blob: clientDataJSON.toString('hex').toUpperCase(),
    HookParameters: [
      {
        HookParameter: {
          HookParameterName: convertStringToHex('auth').toUpperCase(),
          HookParameterValue: verificationData.authData.toString('hex').toUpperCase(),
        },
      },
      {
        HookParameter: {
          HookParameterName: convertStringToHex('x').toUpperCase(),
          HookParameterValue: verificationData.publicKey.x.toString('hex').toUpperCase(),
        },
      }, {
        HookParameter: {
          HookParameterName: convertStringToHex('y').toUpperCase(),
          HookParameterValue: verificationData.publicKey.y.toString('hex').toUpperCase(),
        },
      },
      {
        HookParameter: {
          HookParameterName: convertStringToHex('r').toUpperCase(),
          HookParameterValue: verificationData.signature.r.toString('hex').toUpperCase(),
        },
      },
      {
        HookParameter: {
          HookParameterName: convertStringToHex('s').toUpperCase(),
          HookParameterValue: verificationData.signature.s.toString('hex').toUpperCase(),
        },
      },
      {
        HookParameter: {
          HookParameterName: convertStringToHex('ptr').toUpperCase(),
          HookParameterValue: bufferToHex(new Uint16Array([verificationData.challengePtr]).buffer),
        },
      },
      {
        HookParameter: {
          HookParameterName: convertStringToHex('len').toUpperCase(),
          HookParameterValue: bufferToHex(new Uint16Array([verificationData.challengeLen]).buffer),
        },
      },
    ]
  }, { wallet: genesis })
  clearInterval(intervalId)
  await client.request({ command: 'ledger_accept' as any })
  const tx = await client.request({
    command: 'account_tx',
    account: address,
    ledger_index: 'validated',
    limit: 1,
  })
  console.log(tx.result)
  await client.disconnect()
  return tx.result.transactions[0]
}

export { client, generateWallet, fundWallet, installHook, submitPasskeyTransaction }
