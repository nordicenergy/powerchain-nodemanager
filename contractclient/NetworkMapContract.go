package contractclient

import (
	"errors"
	"math/big"

	log "github.com/sirupsen/logrus"

	"gitlab.com/lition/lition-maker-nodemanager/client"
	internalContract "gitlab.com/lition/lition-maker-nodemanager/contractclient/internalcontract"
	"gitlab.com/lition/lition/accounts/abi/bind"
	"gitlab.com/lition/lition/common"
	"gitlab.com/lition/lition/core/types"
)

type NodeDetails struct {
	Name      string `json:"nodeName,omitempty"`
	Role      string `json:"role,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
	Enode     string `json:"enode,omitempty"`
	IP        string `json:"ip,omitempty"`
}

type NetworkMapContractClient struct {
	client.EthClient
	Auth *bind.TransactOpts
	Ic   *internalContract.ScClient
}

type GetNodeDetailsParam int

type Signature struct {
	V uint8
	R [32]byte
	S [32]byte
}

func (nmc *NetworkMapContractClient) RegisterNode(name string, role string, publicKey string, enode string, ip string) string {

	if nmc.Ic == nil {
		return ""
	}

	nodeList := nmc.GetNodeDetailsList()
	for _, nodeDetails := range nodeList {
		if nodeDetails.Enode == enode {
			return "Exists"
		}
	}

	tx, err := nmc.Ic.RegisterNode(nmc.Auth, name, role, publicKey, enode, ip)
	if err != nil {
		log.Error("RegisterNode: ", err)
		return ""
	}
	return tx.Hash().String()
}

func (nmc *NetworkMapContractClient) GetNodeDetails(i int) NodeDetails {

	if nmc.Ic == nil {
		return NodeDetails{}
	}

	details, err := nmc.Ic.GetNodeDetails(nil, uint16(i))
	if err != nil {
		log.Error("GetNodeDetails: ", err)
		return NodeDetails{}
	}

	return NodeDetails{details.N, details.R, details.P, details.E, details.Ip}
}

func (nmc *NetworkMapContractClient) GetNodeDetailsList() []NodeDetails {

	var list []NodeDetails

	if nmc.Ic == nil {
		return list
	}

	for i := 0; true; i++ {
		details, err := nmc.Ic.GetNodeDetails(nil, uint16(i))
		if err != nil {
			return list
		}
		if details.E != "" && len(details.E) > 0 {
			list = append(list, NodeDetails{details.N, details.R, details.P, details.E, details.Ip})
		} else {
			return list
		}
	}

	return list
}

func (nmc *NetworkMapContractClient) GetNodeCount() int {

	if nmc.Ic == nil {
		return 0
	}

	count, err := nmc.Ic.GetNodesCounter(nil)
	if err != nil {
		log.Error("GetNodeCount", err)
		return 0
	}

	return int(count.Int64())
}

func (nmc *NetworkMapContractClient) UpdateNode(name string, role string, publicKey string, enode string, ip string) string {

	if nmc.Ic == nil {
		return ""
	}
	tx, err := nmc.Ic.UpdateNode(nmc.Auth, name, role, publicKey, enode, ip)
	if err != nil {
		log.Error("UpdateNode: ", err)
		return ""
	}
	return tx.Hash().String()
}

func (nmc *NetworkMapContractClient) GetSignatureHashFromNotary(notary_block int64, miners []common.Address, blocks_mined []uint32, users []common.Address, user_gas []uint64, largest_tx uint64) ([32]byte, error) {
	if nmc.Ic == nil {
		return [32]byte{}, errors.New("NetworkMapContractClient internalContract client not provided")
	}
	return nmc.Ic.GetSignatureHashFromNotary(nil, big.NewInt(notary_block), miners, blocks_mined, users, user_gas, largest_tx)
}

func (nmc *NetworkMapContractClient) GetSignatures(notary_block int64, index int) (Signature, error) {
	if nmc.Ic == nil {
		return Signature{}, errors.New("NetworkMapContractClient internalContract client not provided")
	}
	return nmc.Ic.GetSignatures(nil, big.NewInt(notary_block), big.NewInt(int64(index)))
}

func (nmc *NetworkMapContractClient) GetSignaturesCount(notary_block int64) (*big.Int, error) {
	if nmc.Ic == nil {
		return nil, errors.New("NetworkMapContractClient internalContract client not provided")
	}

	return nmc.Ic.GetSignaturesCount(nil, big.NewInt(notary_block))
}

func (nmc *NetworkMapContractClient) StoreSignature(notary_block int64, sig Signature) (*types.Transaction, error) {
	if nmc.Ic == nil {
		return nil, errors.New("NetworkMapContractClient internalContract client not provided")
	}

	return nmc.Ic.StoreSignature(nmc.Auth, big.NewInt(notary_block), sig.V, sig.R, sig.S)
}

type DeployContractHandler struct {
	binary string
}

func (d DeployContractHandler) Encode() string {
	return d.binary
}
