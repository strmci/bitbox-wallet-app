// SPDX-License-Identifier: Apache-2.0

package btc

import (
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/accounts"
	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/coins/btc/addresses"
	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/coins/btc/blockchain"
	blockchainMock "github.com/BitBoxSwiss/bitbox-wallet-app/backend/coins/btc/blockchain/mocks"
	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/coins/coin"
	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/config"
	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/keystore"
	keystoremock "github.com/BitBoxSwiss/bitbox-wallet-app/backend/keystore/mocks"
	"github.com/BitBoxSwiss/bitbox-wallet-app/backend/signing"
	"github.com/BitBoxSwiss/bitbox-wallet-app/util/logging"
	"github.com/BitBoxSwiss/bitbox-wallet-app/util/socksproxy"
	"github.com/BitBoxSwiss/bitbox-wallet-app/util/test"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func mockKeystore() *keystoremock.KeystoreMock {
	return &keystoremock.KeystoreMock{
		CanSignMessageFunc: func(coin.Code) bool { return true },
		SignBTCMessageFunc: func(_ []byte, _ signing.AbsoluteKeypath, _ signing.ScriptType, _ coin.Code) ([]byte, error) {
			return []byte("signature"), nil
		},
	}
}

func mockAccount(t *testing.T, accountConfig *config.Account) *Account {
	t.Helper()
	code := coin.CodeTBTC
	unit := "TBTC"
	net := &chaincfg.TestNet3Params

	dbFolder := test.TstTempDir("btc-dbfolder")
	defer func() { _ = os.RemoveAll(dbFolder) }()

	coin := NewCoin(
		code, "Bitcoin Testnet", unit, coin.BtcUnitDefault, net, dbFolder, nil, explorer, socksproxy.NewSocksProxy(false, ""))

	blockchainMock := &blockchainMock.BlockchainMock{}
	blockchainMock.MockRegisterOnConnectionErrorChangedEvent = func(f func(error)) {}

	coin.TstSetMakeBlockchain(func() blockchain.Interface { return blockchainMock })

	keypath, err := signing.NewAbsoluteKeypath("m/84'/1'/0'")
	require.NoError(t, err)
	xpub, err := hdkeychain.NewMaster(make([]byte, 32), net)
	require.NoError(t, err)
	xpub, err = xpub.Neuter()
	require.NoError(t, err)

	signingConfigurations := &signing.Configurations{signing.NewBitcoinConfiguration(
		signing.ScriptTypeP2WPKH,
		[]byte{1, 2, 3, 4},
		keypath,
		xpub)}

	defaultConfig := &config.Account{
		Code:                  "accountcode",
		Name:                  "accountname",
		SigningConfigurations: *signingConfigurations,
	}

	if accountConfig == nil {
		accountConfig = defaultConfig
	}

	return NewAccount(
		&accounts.AccountConfig{
			Config:          accountConfig,
			DBFolder:        dbFolder,
			RateUpdater:     nil,
			GetNotifier:     func(signing.Configurations) accounts.Notifier { return nil },
			GetSaveFilename: func(suggestedFilename string) string { return suggestedFilename },
			ConnectKeystore: func() (keystore.Keystore, error) {
				return mockKeystore(), nil
			},
		},
		coin, nil, nil,
		logging.Get().WithGroup("account_test"),
		nil,
	)
}

func TestAccount(t *testing.T) {
	account := mockAccount(t, nil)
	require.False(t, account.Synced())
	require.NoError(t, account.Initialize())
	require.Eventually(t, account.Synced, time.Second, time.Millisecond*200)

	balance, err := account.Balance()
	require.NoError(t, err)
	require.Equal(t, big.NewInt(0), balance.Available().BigInt())
	require.Equal(t, big.NewInt(0), balance.Incoming().BigInt())

	transactions, err := account.Transactions()
	require.NoError(t, err)
	require.Equal(t, accounts.OrderedTransactions{}, transactions)

	spendableOutputs, err := account.SpendableOutputs()
	require.NoError(t, err)
	require.Equal(t, []*SpendableOutput{}, spendableOutputs)
}

func TestReusedAddresses(t *testing.T) {
	script1 := []byte{0x01}
	script2 := []byte{0x02}
	address1 := addresses.NewAddressID(script1)
	address2 := addresses.NewAddressID(script2)
	makeOutput := func(index uint32, pkScript []byte) map[wire.OutPoint]*wire.TxOut {
		return map[wire.OutPoint]*wire.TxOut{
			{Index: index}: wire.NewTxOut(0, pkScript),
		}
	}
	testCases := []struct {
		name               string
		candidateAddresses map[addresses.AddressID]struct{}
		indexedOutputs     map[wire.OutPoint]*wire.TxOut
		want               map[addresses.AddressID]struct{}
	}{
		{
			name: "two indexed outputs on same address",
			candidateAddresses: map[addresses.AddressID]struct{}{
				address1: {},
			},
			indexedOutputs: map[wire.OutPoint]*wire.TxOut{
				{Index: 0}: wire.NewTxOut(0, script1),
				{Index: 1}: wire.NewTxOut(0, script1),
			},
			want: map[addresses.AddressID]struct{}{
				address1: {},
			},
		},
		{
			name: "spent sibling regression",
			candidateAddresses: map[addresses.AddressID]struct{}{
				address1: {},
			},
			indexedOutputs: map[wire.OutPoint]*wire.TxOut{
				{Index: 0}: wire.NewTxOut(0, script1),
				{Index: 1}: wire.NewTxOut(0, script1),
				{Index: 2}: wire.NewTxOut(0, script2),
			},
			want: map[addresses.AddressID]struct{}{
				address1: {},
			},
		},
		{
			name: "single indexed output does not count as reuse",
			candidateAddresses: map[addresses.AddressID]struct{}{
				address1: {},
			},
			indexedOutputs: map[wire.OutPoint]*wire.TxOut{
				{Index: 0}: wire.NewTxOut(0, script1),
				{Index: 1}: wire.NewTxOut(0, script2),
			},
			want: map[addresses.AddressID]struct{}{},
		},
		{
			name: "subset request ignores reuse on other addresses",
			candidateAddresses: map[addresses.AddressID]struct{}{
				address2: {},
			},
			indexedOutputs: map[wire.OutPoint]*wire.TxOut{
				{Index: 0}: wire.NewTxOut(0, script1),
				{Index: 1}: wire.NewTxOut(0, script1),
				{Index: 2}: wire.NewTxOut(0, script2),
			},
			want: map[addresses.AddressID]struct{}{},
		},
		{
			name:               "empty candidate set",
			candidateAddresses: map[addresses.AddressID]struct{}{},
			indexedOutputs:     makeOutput(0, script1),
			want:               map[addresses.AddressID]struct{}{},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, reusedAddresses(testCase.candidateAddresses, testCase.indexedOutputs))
		})
	}
}

func TestInsuredAccountAddresses(t *testing.T) {
	net := &chaincfg.TestNet3Params

	wrapSegKeypath, err := signing.NewAbsoluteKeypath("m/49'/1'/0'")
	require.NoError(t, err)
	wrappedSeed := sha256.Sum256([]byte("wrapped"))
	wrapSegXpub, err := hdkeychain.NewMaster(wrappedSeed[:], net)
	require.NoError(t, err)
	wrapSegXpub, err = wrapSegXpub.Neuter()
	require.NoError(t, err)

	natSegKeypath, err := signing.NewAbsoluteKeypath("m/84'/1'/0'")
	require.NoError(t, err)
	natSegSeed := sha256.Sum256([]byte("native"))
	natSegXpub, err := hdkeychain.NewMaster(natSegSeed[:], net)
	require.NoError(t, err)
	natSegXpub, err = natSegXpub.Neuter()
	require.NoError(t, err)

	signingConfigurations := signing.Configurations{
		signing.NewBitcoinConfiguration(
			signing.ScriptTypeP2WPKHP2SH,
			[]byte{1, 2, 3, 4},
			wrapSegKeypath,
			wrapSegXpub),
		signing.NewBitcoinConfiguration(
			signing.ScriptTypeP2WPKH,
			[]byte{1, 2, 3, 4},
			natSegKeypath,
			natSegXpub),
	}
	account := mockAccount(t, &config.Account{
		Code:                  "accountcode",
		Name:                  "accountname",
		SigningConfigurations: signingConfigurations,
	})
	require.NoError(t, account.Initialize())
	require.Eventually(t, account.Synced, time.Second, time.Millisecond*200)

	// Wrapped segwit stays scanned, but it is no longer exposed in generic receive flows.
	addressList, err := account.GetUnusedReceiveAddresses()
	require.NoError(t, err)
	require.Len(t, addressList, 1)
	require.Len(t, addressList[0].Addresses, 20)
	require.Equal(t, signing.ScriptTypeP2WPKH, *addressList[0].ScriptType)

	// Create a new insured account.
	account2 := mockAccount(t, &config.Account{
		Code:                  "accountcode2",
		Name:                  "accountname2",
		SigningConfigurations: signingConfigurations,
		InsuranceStatus:       "active",
	})

	require.NoError(t, account2.Initialize())
	require.Eventually(t, account2.Synced, time.Second, time.Millisecond*200)

	// native segwit is the only address type available.
	addressList, err = account2.GetUnusedReceiveAddresses()
	require.NoError(t, err)
	require.Len(t, addressList, 1)
	require.Len(t, addressList[0].Addresses, 20)
	require.Equal(t, signing.ScriptTypeP2WPKH, *addressList[0].ScriptType)

}

func TestSignAddress(t *testing.T) {
	account := mockAccount(t, nil)
	require.NoError(t, account.Initialize())
	require.Eventually(t, account.Synced, time.Second, time.Millisecond*200)
	// pt2r is not an available script type in the mocked account.
	_, _, err := SignBTCAddress(account, "Hello there", signing.ScriptTypeP2TR)
	require.Error(t, err)
	address, signature, err := SignBTCAddress(account, "Hello there", signing.ScriptTypeP2WPKH)
	require.NoError(t, err)
	require.NotEmpty(t, address)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("signature")), signature)

}

func TestIsChange(t *testing.T) {
	account := mockAccount(t, nil)
	require.NoError(t, account.Initialize())
	require.Eventually(t, account.Synced, time.Second, time.Millisecond*200)
	account.ensureAddresses()
	for _, subaccunt := range account.subaccounts {
		unusedReceiveAddresses, err := subaccunt.receiveAddresses.GetUnused()
		require.NoError(t, err)
		unusedChangeAddresses, err := subaccunt.changeAddresses.GetUnused()
		require.NoError(t, err)
		// check IsChange returns true for all change addresses
		for _, changeAddress := range unusedChangeAddresses {
			require.True(t, account.IsChange(changeAddress.PubkeyScriptHashHex()))
		}
		// ensure no false positives
		for _, address := range unusedReceiveAddresses {
			require.False(t, account.IsChange(address.PubkeyScriptHashHex()))
		}
	}
}
