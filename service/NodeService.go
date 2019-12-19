package service

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/magiconair/properties"
	log "github.com/sirupsen/logrus"
	"gitlab.com/lition/lition-maker-nodemanager/client"
	"gitlab.com/lition/lition-maker-nodemanager/contractclient"
	internalContract "gitlab.com/lition/lition-maker-nodemanager/contractclient/internalcontract"
	"gitlab.com/lition/lition-maker-nodemanager/util"
	"gitlab.com/lition/lition/accounts/abi/bind"
	"gitlab.com/lition/lition/common"
	"gitlab.com/lition/lition/crypto"
	"gitlab.com/lition/lition/ethclient"
	litionScClient "gitlab.com/lition/lition_contracts/contracts/client"
)

type ConnectionInfo struct {
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Enode string `json:"enode"`
}

type PendingRequests struct {
	NodeName string `json:"nodeName"`
	Enode    string `json:"enode"`
	Message  string `json:"message"`
	EnodeID  string `json:"enodeid"`
	IP       string `json:"ip"`
}

type NodeInfo struct {
	NodeName       string           `json:"nodeName"`
	NodeCount      int              `json:"nodeCount"`
	TotalNodeCount int              `json:"totalNodeCount"`
	Active         string           `json:"active"`
	ConnectionInfo ConnectionInfo   `json:"connectionInfo"`
	Role           string           `json:"role"`
	BlockNumber    int64            `json:"blockNumber"`
	PendingTxCount int              `json:"pendingTxCount"`
	AdminInfo      client.AdminInfo `json:"adminInfo"`
	ChainId        int              `json:"chainId"`
}

type JoinNetworkRequest struct {
	EnodeID   string `json:"enode-id,omitempty"`
	IPAddress string `json:"ip-address,omitempty"`
	Nodename  string `json:"nodename,omitempty"`
	AccPubKey string `json:"acc-pub-key,omitempty"`
	ChainID   string `json:"chain-id,omitempty"`
	Role      string `json:"role,omitempty"`
}

type GetGenesisResponse struct {
	ContstellationPort string `json:"contstellation-port"`
	NetID              string `json:"netID"`
	Genesis            string `json:"genesis"`
}

type GetNmcAddressResponse struct {
	ContstellationPort string `json:"nmcAddress"`
}

type BlockDetailsResponse struct {
	Number           int64                        `json:"number"`
	Hash             string                       `json:"hash"`
	ParentHash       string                       `json:"parentHash"`
	Nonce            string                       `json:"nonce"`
	Sha3Uncles       string                       `json:"sha3Uncles"`
	LogsBloom        string                       `json:"logsBloom"`
	TransactionsRoot string                       `json:"transactionsRoot"`
	StateRoot        string                       `json:"stateRoot"`
	Miner            string                       `json:"miner"`
	Difficulty       int64                        `json:"difficulty"`
	TotalDifficulty  int64                        `json:"totalDifficulty"`
	ExtraData        string                       `json:"extraData"`
	Size             int64                        `json:"size"`
	GasLimit         int64                        `json:"gasLimit"`
	GasUsed          int64                        `json:"gasUsed"`
	Timestamp        int64                        `json:"timestamp"`
	Transactions     []TransactionDetailsResponse `json:"transactions"`
	Uncles           []string                     `json:"uncles"`
	TimeElapsed      int64                        `json:"TimeElapsed"`
}

type TransactionDetailsResponse struct {
	BlockHash        string `json:"blockHash"`
	BlockNumber      int64  `json:"blockNumbe"`
	From             string `json:"from"`
	Gas              int64  `json:"gas"`
	GasPrice         int64  `json:"gasPrice"`
	Hash             string `json:"hash"`
	Input            string `json:"input"`
	Nonce            int64  `json:"nonce"`
	To               string `json:"to"`
	TransactionIndex int64  `json:"transactionIndex"`
	Value            int64  `json:"value"`
	V                string `json:"v"`
	R                string `json:"r"`
	S                string `json:"s"`
	TransactionType  string `json:"transactionType"`
	TimeElapsed      int64  `json:"TimeElapsed"`
}

type TransactionReceiptResponse struct {
	BlockHash         string                         `json:"blockHash"`
	BlockNumber       int64                          `json:"blockNumber"`
	ContractAddress   string                         `json:"contractAddress"`
	CumulativeGasUsed int64                          `json:"cumulativeGasUsed"`
	From              string                         `json:"from"`
	Gas               int64                          `json:"gas"`
	GasPrice          int64                          `json:"gasPrice"`
	GasUsed           int64                          `json:"gasUsed"`
	Input             string                         `json:"input"`
	Logs              []Logs                         `json:"logs"`
	LogsBloom         string                         `json:"logsBloom"`
	Nonce             int64                          `json:"nonce"`
	Root              string                         `json:"root"`
	To                string                         `json:"to"`
	TransactionHash   string                         `json:"transactionHash"`
	TransactionIndex  int64                          `json:"transactionIndex"`
	Value             int64                          `json:"value"`
	V                 string                         `json:"v"`
	R                 string                         `json:"r"`
	S                 string                         `json:"s"`
	TransactionType   string                         `json:"transactionType"`
	TimeElapsed       int64                          `json:"TimeElapsed"`
	DecodedInputs     []contractclient.ParamTableRow `json:"decodedInputs,omitempty"`
	FunctionDetails   string                         `json:"functionDetails,omitempty"`
	DecodeFailed      DecodeFailure                  `json:"decodeFailed,omitempty"`
}

type DecodeFailure struct {
	Label string `json:"label"`
	Type  string `json:"type"`
}

type Logs struct {
	Address          string   `json:"address"`
	BlockHash        string   `json:"blockHash"`
	BlockNumber      int64    `json:"blockNumber"`
	Data             string   `json:"data"`
	LogIndex         int64    `json:"logIndex"`
	Topics           []string `json:"topics"`
	TransactionHash  string   `json:"transactionHash"`
	TransactionIndex int64    `json:"transactionIndex"`
}

type JoinNetworkResponse struct {
	EnodeID string `json:"enode-id"`
	Status  string `json:"status"`
}

type ContractJson struct {
	Filename        string `json:"filename"`
	Interface       string `json:"interface"`
	Bytecode        string `json:"bytecode"`
	ContractAddress string `json:"address"`
	Json            string `json:"json"`
}

type CreateNetworkScriptArgs struct {
	Nodename          string `json:"nodename,omitempty"`
	CurrentIP         string `json:"currentIP,omitempty"`
	RPCPort           string `json:"rpcPort,omitempty"`
	WhisperPort       string `json:"whisperPort,omitempty"`
	ConstellationPort string `json:"constellationPort,omitempty"`
	NodeManagerPort   string `json:"nodeManagerPort,omitempty"`
}

type JoinNetworkScriptArgs struct {
	Nodename              string `json:"nodename,omitempty"`
	CurrentIP             string `json:"currentIP,omitempty"`
	RPCPort               string `json:"rpcPort,omitempty"`
	WhisperPort           string `json:"whisperPort,omitempty"`
	ConstellationPort     string `json:"constellationPort,omitempty"`
	NodeManagerPort       string `json:"nodeManagerPort,omitempty"`
	MasterNodeManagerPort string `json:"masterNodeManagerPort,omitempty"`
	MasterIP              string `json:"masterIP,omitempty"`
}

type SuccessResponse struct {
	Status string `json:"statusMessage"`
}

type SuccessResponseBool struct {
	Status bool `json:"statusMessage"`
}

type LatestBlockResponse struct {
	LatestBlockNumber int64 `json:"latestBlockNumber"`
	TimeElapsed       int64 `json:"TimeElapsed"`
}

type NodeList struct {
	NodeName  string `json:"nodeName"`
	Role      string `json:"role,omitempty"`
	PublicKey string `json:"publicKey"`
	IP        string `json:"ip,omitempty"`
	Enode     string `json:"enode,omitempty"`
}

type MailServerConfig struct {
	Host          string `json:"smtpServerHost"`
	Port          string `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	RecipientList string `json:"recipientList"`
}

type LatencyResponse struct {
	EnodeID string `json:"enode-id"`
	Latency string `json:"latency"`
}

type NodeServiceImpl struct {
	Url                      string
	PowerChainContractClient     *litionScClient.ContractClient
	NodeAccAddress           string
	MiningRegisteredChan     chan struct{}
	MiningRegistered         bool
	NotaryPeriod             int64
	Nms                      *contractclient.NetworkMapContractClient
	LastInternalNotary       int64
	LastPowerChainScNotaryBlock  int64
	LastProcessedNotaryBlock int64
	NotaryInvokedCounter     uint32
}

type ChartInfo struct {
	TimeStamp        int `json:"timeStamp"`
	BlockCount       int `json:"blockCount"`
	TransactionCount int `json:"transactionCount"`
}

type ContractTableRow struct {
	ContractAdd  string `json:"contractAddress"`
	ContractName string `json:"contractName"`
	ABIContent   string `json:"abi"`
	Sender       string `json:"sender"`
	ContractType string `json:"contractType"`
	Description  string `json:"description"`
	Timestamp    string `json:"timestamp"`
}

type ContractCounter struct {
	TotalContracts int `json:"totalContracts"`
	ABIavailable   int `json:"abis"`
}

type CrawledABI struct {
	Filename         string `json:"filename"`
	ModificationTime int64  `json:"modificationTime"`
	Processed        bool   `json:"processed"`
	Contractname     string `json:"contractname"`
}

type contractJSONTruffle struct {
	Abi          []interface{} `json:"abi"`
	Interface    []interface{} `json:"interface"`
	Bytecode     string        `json:"bytecode"`
	ContractName string        `json:"contractName"`
}

type ethAccount struct {
	AccountAddress string `json:"accountAddress"`
	Coinbase       bool   `json:"coinbase"`
	Balance        string `json:"balance"`
}

var txnMap = map[string]TransactionReceiptResponse{}
var abiMap = map[string]string{}
var contractCrawlerMutex = 0
var crawledABIs []CrawledABI
var abiCrawlerMutex = 0

var contDescriptionMap = map[string]string{}
var contTypeMap = map[string]string{}
var contTimeMap = map[string]string{}
var contSenderMap = map[string]string{}
var contNameMap = map[string]string{}
var chartSize = 10
var warning = 0
var lastCrawledBlock = 0
var mailServerConfig MailServerConfig

func NewNodeServiceImpl(url string, litionContractClient *litionScClient.ContractClient, nodeAccAddress string, nms *contractclient.NetworkMapContractClient) (*NodeServiceImpl, error) {
	neNodeServiceImpl := new(NodeServiceImpl)

	chainStaticDetails, err := litionContractClient.GetChainStaticDetails()
	if err != nil {
		return nil, err
	}
	neNodeServiceImpl.NotaryPeriod = chainStaticDetails.NotaryPeriod.Int64()

	neNodeServiceImpl.Url = url
	neNodeServiceImpl.PowerChainContractClient = litionContractClient
	neNodeServiceImpl.NodeAccAddress = nodeAccAddress
	neNodeServiceImpl.Nms = nms
	neNodeServiceImpl.MiningRegistered = true
	neNodeServiceImpl.MiningRegisteredChan = nil
	neNodeServiceImpl.LastInternalNotary = 0
	neNodeServiceImpl.LastPowerChainScNotaryBlock = 0
	neNodeServiceImpl.LastProcessedNotaryBlock = 0
	neNodeServiceImpl.NotaryInvokedCounter = 0

	return neNodeServiceImpl, nil
}

func (nsi *NodeServiceImpl) ethProposeValidator(url string, validatorAddress string, vote bool) error {
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}

	return ethClient.ProposeValidator(validatorAddress, vote)
}

func (nsi *NodeServiceImpl) getGenesis(url string) (response GetGenesisResponse) {
	var netId, constl string
	existsA := util.PropertyExists("NETWORK_ID", "/home/setup.conf")
	existsB := util.PropertyExists("CONSTELLATION_PORT", "/home/setup.conf")
	if existsA != "" && existsB != "" {
		p := properties.MustLoadFile("/home/setup.conf", properties.UTF8)
		netId = util.MustGetString("NETWORK_ID", p)
		constl = util.MustGetString("CONSTELLATION_PORT", p)
	}
	b, err := ioutil.ReadFile("/home/node/genesis.json")
	if err != nil {
		//log.Println(err)
	}
	genesis := string(b)
	genesis = strings.Replace(genesis, "\n", "", -1)

	response = GetGenesisResponse{constl, netId, genesis}
	return response
}

func (nsi *NodeServiceImpl) getNmcAddress() (response GetNmcAddressResponse) {
	var contractAdd string
	exists := util.PropertyExists("CONTRACT_ADD", "/home/setup.conf")
	if exists != "" {
		p := properties.MustLoadFile("/home/setup.conf", properties.UTF8)
		contractAdd = util.MustGetString("CONTRACT_ADD", p)
	}
	response = GetNmcAddressResponse{contractAdd}
	return response
}

//@TODO: If this function is repeatedly called from UI, please cache the static informations.
func (nsi *NodeServiceImpl) getCurrentNode(url string) NodeInfo {
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}

	nsi.InitInternalContract(url)

	totalCount := nsi.Nms.GetNodeCount()
	var activeStatus string
	active := ethClient.NetListening()
	if active == true {
		activeStatus = "active"
	} else {
		activeStatus = "inactive"
	}
	otherPeersResponse := ethClient.AdminPeers()
	count := len(otherPeersResponse)
	count = count + 1

	//@TODO: Cant the regex be simply start*.sh ?
	r, _ := regexp.Compile("[s][t][a][r][t][_][A-Za-z0-9]*[.][s][h]")

	//@TODO: Use of absolute path (starting with "/") is highly error prone
	files, err := ioutil.ReadDir("/home/node")
	if err != nil {
		log.Println(err)
	}
	var nodename string
	for _, f := range files {
		match, _ := regexp.MatchString("[s][t][a][r][t][_][A-Za-z0-9]*[.][s][h]", f.Name())
		if match {
			nodename = r.FindString(f.Name())
		}
	}

	//@TODO: use grouping in regex to find the name of the node. Refer to whats app message.
	nodename = strings.TrimSuffix(nodename, ".sh")
	nodename = strings.TrimPrefix(nodename, "start_")

	var ipAddr, rpcPort, nodeName string
	var p *properties.Properties
	p = properties.MustLoadFile("/home/setup.conf", properties.UTF8)
	existsA := util.PropertyExists("CURRENT_IP", "/home/setup.conf")
	existsC := util.PropertyExists("RPC_PORT", "/home/setup.conf")
	existsD := util.PropertyExists("NODENAME", "/home/setup.conf")
	if existsA != "" && existsC != "" && existsD != "" {
		ipAddr = util.MustGetString("CURRENT_IP", p)
		rpcPort = util.MustGetString("RPC_PORT", p)
		nodeName = util.MustGetString("NODENAME", p)
	}
	rpcPortInt, err := strconv.Atoi(rpcPort)
	if err != nil {
		log.Println(err)
	}

	thisAdminInfo := ethClient.AdminNodeInfo()
	enode := thisAdminInfo.Enode

	pendingTxResponse := ethClient.PendingTransactions()
	pendingTxCount := len(pendingTxResponse)

	blockNumber := ethClient.BlockNumber()
	blockNumberInt := util.HexStringtoInt64(blockNumber)

	role := util.MustGetString("ROLE", p)
	chainId, err := strconv.Atoi(util.MustGetString("CHAIN_ID", p))
	if err != nil {
		log.Println(err)
	}

	conn := ConnectionInfo{ipAddr, rpcPortInt, enode}
	responseObj := NodeInfo{nodeName, count, totalCount, activeStatus, conn, role, blockNumberInt, pendingTxCount, thisAdminInfo, chainId}
	return responseObj
}

func (nsi *NodeServiceImpl) getOtherPeer(peerId string, url string) client.AdminPeers {
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	otherPeersResponse := ethClient.AdminPeers()
	for _, item := range otherPeersResponse {
		if item.ID == peerId {
			peerResponse := item
			return peerResponse
		}
	}
	return client.AdminPeers{}
}

func (nsi *NodeServiceImpl) getOtherPeers(url string) []client.AdminPeers {
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	otherPeersResponse := ethClient.AdminPeers()
	return otherPeersResponse
}

func (nsi *NodeServiceImpl) getPendingTransactions(url string) []TransactionDetailsResponse {
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	clientPendingTxResponses := ethClient.PendingTransactions()

	pendingTxResponse := make([]TransactionDetailsResponse, len(clientPendingTxResponses))

	for i, clientPendingTxResponse := range clientPendingTxResponses {

		pendingTxResponse[i] = ConvertToReadable(clientPendingTxResponse, true, true)
	}

	return pendingTxResponse
}

func (nsi *NodeServiceImpl) getBlockInfo(blockno int64, url string) BlockDetailsResponse {
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	blockNoHex := strconv.FormatInt(blockno, 16)
	bNoHex := fmt.Sprint("0x", blockNoHex)
	var blockResponse BlockDetailsResponse
	blockResponseClient := ethClient.GetBlockByNumber(bNoHex)
	currentTime := time.Now().Unix()
	creationTime := util.HexStringtoInt64(blockResponseClient.Timestamp)
	elapsedTime := currentTime - creationTime
	blockResponse.TimeElapsed = elapsedTime

	//@TODO: Create a utility function to convert block object to readable object.
	blockResponse.Number = util.HexStringtoInt64(blockResponseClient.Number)
	blockResponse.Difficulty = util.HexStringtoInt64(blockResponseClient.Difficulty)
	blockResponse.TotalDifficulty = util.HexStringtoInt64(blockResponseClient.TotalDifficulty)
	blockResponse.Size = util.HexStringtoInt64(blockResponseClient.Size)
	blockResponse.GasLimit = util.HexStringtoInt64(blockResponseClient.GasLimit)
	blockResponse.GasUsed = util.HexStringtoInt64(blockResponseClient.GasUsed)
	blockResponse.Timestamp = util.HexStringtoInt64(blockResponseClient.Timestamp)
	blockResponse.Hash = blockResponseClient.Hash
	blockResponse.ParentHash = blockResponseClient.ParentHash
	blockResponse.Nonce = blockResponseClient.Nonce
	blockResponse.Sha3Uncles = blockResponseClient.Sha3Uncles
	blockResponse.LogsBloom = blockResponseClient.LogsBloom
	blockResponse.TransactionsRoot = blockResponseClient.TransactionsRoot
	blockResponse.StateRoot = blockResponseClient.StateRoot
	blockResponse.Miner = blockResponseClient.Miner
	blockResponse.ExtraData = blockResponseClient.ExtraData
	blockResponse.Uncles = blockResponseClient.Uncles
	txnNo := len(blockResponseClient.Transactions)
	txResponse := make([]TransactionDetailsResponse, txnNo)
	for i, clientTransactions := range blockResponseClient.Transactions {

		txGetClient := ethClient.GetTransactionByHash(clientTransactions.Hash)
		private := ethClient.GetQuorumPayload(txGetClient.Input)
		txResponse[i] = ConvertToReadable(clientTransactions, false, (private == "0x"))

	}
	blockResponse.Transactions = txResponse
	return blockResponse
}

func (nsi *NodeServiceImpl) getLatestBlockInfo(count string, reference string, url string) []BlockDetailsResponse {
	countValInt, _ := strconv.Atoi(count)
	countVal := int64(countValInt)
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	var blockNumber int64
	if reference == "" {
		blockNumber = util.HexStringtoInt64(ethClient.BlockNumber())
	} else {
		var err error
		blockNumber, err = strconv.ParseInt(reference, 10, 64)
		if err != nil {
			fmt.Println(err)
		}
		blockNumber = blockNumber - 1
	}
	start := blockNumber - countVal + 1
	blockResponse := make([]BlockDetailsResponse, countVal)

	//@TODO: call the utility function to convert to readable block object
	for i := start; i <= blockNumber; i++ {
		blockNoHex := strconv.FormatInt(i, 16)
		bNoHex := fmt.Sprint("0x", blockNoHex)
		blockResponseClient := ethClient.GetBlockByNumber(bNoHex)
		blockResponse[blockNumber-i].Number = util.HexStringtoInt64(blockResponseClient.Number)
		blockResponse[blockNumber-i].Hash = blockResponseClient.Hash
		currentTime := time.Now().Unix()
		creationTime := util.HexStringtoInt64(blockResponseClient.Timestamp)
		elapsedTime := currentTime - creationTime
		blockResponse[blockNumber-i].TimeElapsed = elapsedTime
		txnNo := len(blockResponseClient.Transactions)
		txResponse := make([]TransactionDetailsResponse, txnNo)

		for i, clientTransactions := range blockResponseClient.Transactions {

			txGetClient := ethClient.GetTransactionByHash(clientTransactions.Hash)
			private := ethClient.GetQuorumPayload(txGetClient.Input)
			txResponse[i] = ConvertToReadable(clientTransactions, false, (private == "0x"))

		}

		blockResponse[blockNumber-i].Transactions = txResponse
	}
	return blockResponse
}

func (nsi *NodeServiceImpl) getLatestTransactionInfo(count string, url string) []BlockDetailsResponse {
	countValInt, _ := strconv.Atoi(count)
	countVal := int64(countValInt)
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	blockNumber := util.HexStringtoInt64(ethClient.BlockNumber())
	start := blockNumber - countVal + 1
	blockResponse := make([]BlockDetailsResponse, countVal)
	for i := start; i <= blockNumber; i++ {
		blockNoHex := strconv.FormatInt(i, 16)
		bNoHex := fmt.Sprint("0x", blockNoHex)
		blockResponseClient := ethClient.GetBlockByNumber(bNoHex)
		currentTime := time.Now().Unix()
		creationTime := util.HexStringtoInt64(blockResponseClient.Timestamp)
		elapsedTime := currentTime - creationTime
		blockResponse[blockNumber-i].TimeElapsed = elapsedTime
		blockResponse[blockNumber-i].Number = util.HexStringtoInt64(blockResponseClient.Number)
		txnNo := len(blockResponseClient.Transactions)
		txResponse := make([]TransactionDetailsResponse, txnNo)

		for i, clientTransactions := range blockResponseClient.Transactions {

			txGetClient := ethClient.GetTransactionByHash(clientTransactions.Hash)
			private := ethClient.GetQuorumPayload(txGetClient.Input)
			txResponse[i] = ConvertToReadable(clientTransactions, false, (private == "0x"))

		}

		blockResponse[blockNumber-i].Transactions = txResponse
	}
	return blockResponse
}

func (nsi *NodeServiceImpl) getTransactionInfo(txno string, url string) TransactionDetailsResponse {
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	var txResponse TransactionDetailsResponse
	txResponseClient := ethClient.GetTransactionByHash(txno)

	private := ethClient.GetQuorumPayload(txResponseClient.Input)
	txResponse = ConvertToReadable(txResponseClient, false, (private == "0x"))

	blockResponseClient := ethClient.GetBlockByNumber(txResponseClient.BlockNumber)
	currentTime := time.Now().Unix()
	creationTime := util.HexStringtoInt64(blockResponseClient.Timestamp)
	elapsedTime := currentTime - creationTime
	txResponse.TimeElapsed = elapsedTime
	return txResponse
}

func (nsi *NodeServiceImpl) getTransactionReceipt(txno string, url string) TransactionReceiptResponse {
	//if txnMap[txno].TransactionHash == "" {
	log.Println("getTransactionReceipt: called with params txno: " + txno + "; url: " + url)
	txResponse := populateTransactionObject(txno, url)
	log.Println("getTransactionReceipt: populateTransactionObject returned ", txResponse)
	decodeTransactionObject(&txResponse, url)
	log.Println("getTransactionReceipt: decodeTransactionObject returned ", txResponse)

	return txResponse
}

func populateTransactionObject(txno string, url string) TransactionReceiptResponse {
	ethClient := client.EthClient{url}
	getTransaction := ethClient.GetTransactionByHash(txno)
	var txResponse TransactionReceiptResponse
	getTransactionReceipt := ethClient.GetTransactionReceipt(txno)
	txResponse.BlockNumber = util.HexStringtoInt64(getTransactionReceipt.BlockNumber)
	txResponse.CumulativeGasUsed = util.HexStringtoInt64(getTransactionReceipt.CumulativeGasUsed)
	txResponse.GasUsed = util.HexStringtoInt64(getTransactionReceipt.GasUsed)
	txResponse.TransactionIndex = util.HexStringtoInt64(getTransactionReceipt.TransactionIndex)
	txResponse.BlockHash = getTransactionReceipt.BlockHash
	txResponse.From = getTransactionReceipt.From
	txResponse.ContractAddress = getTransactionReceipt.ContractAddress
	txResponse.LogsBloom = getTransactionReceipt.LogsBloom
	txResponse.Root = getTransactionReceipt.Root
	txResponse.To = getTransactionReceipt.To
	txResponse.TransactionHash = getTransactionReceipt.TransactionHash
	txResponse.Gas = util.HexStringtoInt64(getTransaction.Gas)
	txResponse.GasPrice = util.HexStringtoInt64(getTransaction.GasPrice)
	txResponse.Input = getTransaction.Input
	txResponse.Nonce = util.HexStringtoInt64(getTransaction.Nonce)
	txResponse.Value = util.HexStringtoInt64(getTransaction.Value)
	txResponse.V = getTransaction.V
	txResponse.R = getTransaction.R
	txResponse.S = getTransaction.S
	eventNo := len(getTransactionReceipt.Logs)
	txResponseBuffer := make([]Logs, eventNo)
	for i := 0; i < eventNo; i++ {
		txResponseBuffer[i].BlockNumber = util.HexStringtoInt64(getTransactionReceipt.Logs[i].BlockNumber)
		txResponseBuffer[i].LogIndex = util.HexStringtoInt64(getTransactionReceipt.Logs[i].LogIndex)
		txResponseBuffer[i].TransactionIndex = util.HexStringtoInt64(getTransactionReceipt.Logs[i].TransactionIndex)
		txResponseBuffer[i].Address = getTransactionReceipt.Logs[i].Address
		txResponseBuffer[i].BlockHash = getTransactionReceipt.Logs[i].BlockHash
		txResponseBuffer[i].Data = getTransactionReceipt.Logs[i].Data
		txResponseBuffer[i].TransactionHash = getTransactionReceipt.Logs[i].TransactionHash
		txResponseBuffer[i].Topics = getTransactionReceipt.Logs[i].Topics
	}
	txResponse.Logs = txResponseBuffer
	blockResponseClient := ethClient.GetBlockByNumber(getTransactionReceipt.BlockNumber)
	currentTime := time.Now().Unix()
	creationTime := util.HexStringtoInt64(blockResponseClient.Timestamp)
	elapsedTime := currentTime - creationTime
	txResponse.TimeElapsed = elapsedTime
	return txResponse
}

func decodeTransactionObject(txnDetails *TransactionReceiptResponse, url string) {
	var powerchainPayload string
	//var decoded bool

	ethClient := client.EthClient{url}

	if util.HexStringtoInt64(txnDetails.V) == 37 || util.HexStringtoInt64(txnDetails.V) == 38 {
		log.Println("decodeTransactionObject: processing powerchain private transaction, calling ethClient.GetQuorumPayload with param ", txnDetails.Input)
		powerchainPayload = ethClient.GetQuorumPayload(txnDetails.Input)
		log.Println("decodeTransactionObject: ethClient.GetQuorumPayload returned ", powerchainPayload)
		if powerchainPayload == "0x" {
			txnDetails.TransactionType = "Hash Only"
		} else {
			txnDetails.TransactionType = "Private"
		}
	} else {
		txnDetails.TransactionType = "Public"

	}
	if txnDetails.ContractAddress == "" {
		if txnDetails.TransactionType == "Private" && abiMap[txnDetails.To] != "" && abiMap[txnDetails.To] != "missing" {
			txnDetails.Input = powerchainPayload
			decodedData, functionDetails := contractclient.ABIParser(txnDetails.To, abiMap[txnDetails.To], powerchainPayload)
			if decodedData[0].Key == "decodeFailed" {
				var decodeFail DecodeFailure
				decodeFail.Label = decodedData[0].Value
				decodeFail.Type = "red"
				txnDetails.DecodeFailed = decodeFail
			} else {
				txnDetails.DecodedInputs = decodedData
			}
			if functionDetails != "" {
				txnDetails.FunctionDetails = functionDetails
				//decoded = true
			}
		} else if txnDetails.TransactionType == "Public" && abiMap[txnDetails.To] != "" && abiMap[txnDetails.To] != "missing" {
			decodedData, functionDetails := contractclient.ABIParser(txnDetails.To, abiMap[txnDetails.To], txnDetails.Input)
			if decodedData[0].Key == "decodeFailed" {
				var decodeFail DecodeFailure
				decodeFail.Label = decodedData[0].Value
				decodeFail.Type = "red"
				txnDetails.DecodeFailed = decodeFail
			} else {
				txnDetails.DecodedInputs = decodedData
			}
			if functionDetails != "" {
				txnDetails.FunctionDetails = functionDetails
				//decoded = true
			}
		} else if txnDetails.TransactionType == "Hash Only" {
			var decodeFail DecodeFailure
			decodeFail.Label = "Hash Only Transaction"
			decodeFail.Type = "red"
			txnDetails.DecodeFailed = decodeFail
			//decoded = true
		} else if abiMap[txnDetails.To] == "" {
			if txnDetails.Input == "0x" && txnDetails.Value != 0 {
				var decodeFail DecodeFailure
				decodeFail.Label = "Ether Transfer"
				decodeFail.Type = "yellow"
				txnDetails.DecodeFailed = decodeFail
				//decoded = true
			} else {
				var decodeFail DecodeFailure
				decodeFail.Label = "Decode in Progress"
				decodeFail.Type = "yellow"
				txnDetails.DecodeFailed = decodeFail
			}
		} else if abiMap[txnDetails.To] == "missing" {
			var decodeFail DecodeFailure
			decodeFail.Label = "ABI Missing"
			decodeFail.Type = "red"
			txnDetails.DecodeFailed = decodeFail
		}
	}
}

func calculateTimeElapsed(txnDetails *TransactionReceiptResponse, url string) {
	ethClient := client.EthClient{url}
	getTransactionReceipt := ethClient.GetTransactionReceipt(txnDetails.TransactionHash)
	blockResponseClient := ethClient.GetBlockByNumber(getTransactionReceipt.BlockNumber)
	currentTime := time.Now().Unix()
	creationTime := util.HexStringtoInt64(blockResponseClient.Timestamp)
	elapsedTime := currentTime - creationTime
	txnDetails.TimeElapsed = elapsedTime
}

func (nsi *NodeServiceImpl) joinRequestResponse(enode string, status string) SuccessResponse {
	var successResponse SuccessResponse
	var enodeString []string
	var ipString []string

	//@TODO: Use regex grouping to extract parts
	enodeVal := strings.TrimPrefix(enode, "enode://")
	enodeString = strings.Split(enodeVal, "@")
	ipString = strings.Split(enodeString[1], ":")
	ip := ipString[0]
	successResponse.Status = fmt.Sprintf("Successfully updated status of %s node with IP: %s to %s", nameMap[enode], ip, status)
	return successResponse
}

func (nsi *NodeServiceImpl) deployContract(pubKeys []string, fileName []string, private bool, url string) []ContractJson {
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}

	if private == true && pubKeys[0] == "" {
		nsi.InitInternalContract(url)
		enode := ethClient.AdminNodeInfo().ID
		peerNo := nsi.Nms.GetNodeCount()
		publicKeys := make([]string, peerNo-1)
		for i := 0; i < peerNo; i++ {
			if enode != nsi.Nms.GetNodeDetails(i).Enode {
				publicKeys[i-1] = nsi.Nms.GetNodeDetails(i).PublicKey
			}
		}
		pubKeys = publicKeys
	}
	var solc string
	if solc == "" { //@TODO huh ???
		solc = "solc"
	}
	fileNo := len(fileName)
	var contractJsonArr []ContractJson
	for i := 0; i < fileNo; i++ {
		var binOut bytes.Buffer
		var errorstring bytes.Buffer
		cmd := exec.Command(solc, "-o", ".", "--overwrite", "--bin", fileName[i])
		cmd = exec.Command(solc, "--bin", fileName[i])
		cmd.Stdout = &binOut
		cmd.Stderr = &errorstring
		err := cmd.Run()
		contractJsonError := make([]ContractJson, 1)
		if err != nil {
			fmt.Println(fmt.Sprint(err) + ": " + errorstring.String())
			contractJsonError[0].Filename = strings.Replace(fileName[i], ".sol", "", -1)
			contractJsonError[0].Json = "Compilation Failed: JSON could not be created"
			contractJsonError[0].Bytecode = "Compilation Failed: " + errorstring.String()
		}
		var abiOut bytes.Buffer
		cmd = exec.Command(solc, "-o", ".", "--overwrite", "--abi", fileName[i])
		cmd = exec.Command(solc, "--abi", fileName[i])
		cmd.Stdout = &abiOut
		cmd.Stderr = &errorstring
		err = cmd.Run()
		if err != nil {
			fmt.Println(fmt.Sprint(err) + ": " + errorstring.String())
			contractJsonError[0].Interface = "Compilation Failed: " + errorstring.String()
			contractJsonError[0].ContractAddress = "0x"
			contractJsonArr = append(contractJsonArr, contractJsonError...)
			continue
		}

		bytecode := binOut.String()
		var contractNames []string

		reStart := regexp.MustCompile("Binary?")
		reEnd := regexp.MustCompile("=======")
		reContName := regexp.MustCompile(`.sol:(.+)?=======`)

		res := reContName.FindStringSubmatch(bytecode)
		contractNames = append(contractNames, strings.Split(res[1], " ")[0])
		delimiterFirst := reEnd.FindStringIndex(bytecode)
		bytecode = bytecode[delimiterFirst[1]:]
		delimiterSecond := reEnd.FindStringIndex(bytecode)
		bytecode = bytecode[delimiterSecond[1]:]
		contractBytecodesAll := reStart.FindAllStringIndex(bytecode, -1)
		contractJsonArrInternal := make([]ContractJson, len(contractBytecodesAll))

		for j := 0; j < len(contractBytecodesAll); j++ {
			var thisContractBytecode string
			contractBytecodes := reStart.FindStringIndex(bytecode)
			start := contractBytecodes[1]
			start = start + 2
			if j != (len(contractBytecodesAll) - 1) {
				delimiter := reEnd.FindStringIndex(bytecode)
				thisContractBytecode = bytecode[start : delimiter[1]-1]
			} else {
				thisContractBytecode = bytecode[start:]
			}
			thisContractBytecode = "0x" + thisContractBytecode
			thisContractBytecode = strings.Replace(thisContractBytecode, " ", "", -1)
			thisContractBytecode = strings.Replace(thisContractBytecode, "=", "", -1)
			thisContractBytecode = strings.Replace(thisContractBytecode, "\n", "", -1)
			contractJsonArrInternal[j].Bytecode = thisContractBytecode
			reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
			byteCodeSanitized := reg.ReplaceAllString(thisContractBytecode, "")

			contractAddress := ethClient.DeployContracts(byteCodeSanitized, pubKeys, private)
			contractJsonArrInternal[j].ContractAddress = contractAddress

			path := "./contracts"
			if _, err := os.Stat(path); os.IsNotExist(err) {
				os.Mkdir(path, 0775)
			}
			bytecode = bytecode[start:]

			if j != (len(contractBytecodesAll) - 1) {
				delimiterFirst := reEnd.FindStringIndex(bytecode)
				bytecode = bytecode[delimiterFirst[1]:]
				res := reContName.FindStringSubmatch(bytecode)
				contractNames = append(contractNames, strings.Split(res[1], " ")[0])
				delimiterSecond := reEnd.FindStringIndex(bytecode)
				bytecode = bytecode[delimiterSecond[1]:]
			}

			path = "./contracts/" + contractAddress + "_" + contractNames[j]
			if _, err := os.Stat(path); os.IsNotExist(err) {
				os.Mkdir(path, 0775)
			}
			contractJsonArrInternal[j].Filename = contractNames[j]
		}

		abiString := abiOut.String()
		reStartABI := regexp.MustCompile("ABI?")
		delimiterFirst = reEnd.FindStringIndex(abiString)
		abiString = abiString[delimiterFirst[1]:]
		delimiterSecond = reEnd.FindStringIndex(abiString)
		abiString = abiString[delimiterSecond[1]:]
		contractABIAll := reStartABI.FindAllStringIndex(abiString, -1)
		for j := 0; j < len(contractABIAll); j++ {
			var thisContractABI string
			contractABIs := reStartABI.FindStringIndex(abiString)
			start := contractABIs[1]
			start = start + 2
			if j != (len(contractABIAll) - 1) {
				delimiter := reEnd.FindStringIndex(abiString)
				thisContractABI = abiString[start : delimiter[1]-1]
			} else {
				thisContractABI = abiString[start:]
			}
			thisContractABI = strings.Replace(thisContractABI, " ", "", -1)
			thisContractABI = strings.Replace(thisContractABI, "=", "", -1)
			thisContractABI = strings.Replace(thisContractABI, "\n", "", -1)
			contractJsonArrInternal[j].Interface = thisContractABI
			if j != (len(contractABIAll) - 1) {
				abiString = abiString[start:]
				delimiterFirst := reEnd.FindStringIndex(abiString)
				abiString = abiString[delimiterFirst[1]:]
				delimiterSecond := reEnd.FindStringIndex(abiString)
				abiString = abiString[delimiterSecond[1]:]
			}
		}

		for j := 0; j < len(contractJsonArrInternal); j++ {
			js := util.ComposeJSON(contractJsonArrInternal[j].Interface, contractJsonArrInternal[j].Bytecode, contractJsonArrInternal[j].ContractAddress)
			contractJsonArrInternal[j].Json = strings.Replace(strings.Replace(js, "\n", "", -1), "\\", "", -1)

			path := "./contracts/" + contractJsonArrInternal[j].ContractAddress + "_" + contractJsonArrInternal[j].Filename

			filePath := path + "/" + contractJsonArrInternal[j].Filename + ".json"
			jsByte := []byte(js)
			err = ioutil.WriteFile(filePath, jsByte, 0775)
			if err != nil {
				fmt.Println(err)
			}
			abi := []byte(contractJsonArrInternal[j].Interface)
			err = ioutil.WriteFile(path+"/ABI", abi, 0775)
			if err != nil {
				fmt.Println(err)
			}
			bin := []byte(contractJsonArrInternal[j].Bytecode)
			err = ioutil.WriteFile(path+"/BIN", bin, 0775)
			if err != nil {
				fmt.Println(err)
			}
			contNameMap[contractJsonArrInternal[j].ContractAddress] = contractJsonArrInternal[j].Filename
			contTimeMap[contractJsonArrInternal[j].ContractAddress] = strconv.Itoa(int(time.Now().Unix()))
			abiMap[contractJsonArrInternal[j].ContractAddress] = contractJsonArrInternal[j].Interface
		}

		contractJsonArr = append(contractJsonArr, contractJsonArrInternal...)
	}
	return contractJsonArr
}

func (nsi *NodeServiceImpl) latestBlockDetails(url string) LatestBlockResponse {
	var latestBlockResponse LatestBlockResponse
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	currentTime := time.Now().Unix()
	blockNumber := ethClient.BlockNumber()
	blockResponseClient := ethClient.GetBlockByNumber(blockNumber)
	blockNumberInt := util.HexStringtoInt64(blockNumber)
	creationTime := blockResponseClient.Timestamp
	creationTimeInt := util.HexStringtoInt64(creationTime)
	elapsedTime := currentTime - creationTimeInt
	latestBlockResponse.LatestBlockNumber = blockNumberInt
	latestBlockResponse.TimeElapsed = elapsedTime
	return latestBlockResponse
}

func (nsi *NodeServiceImpl) latency(url string) []LatencyResponse {
	nsi.InitInternalContract(url)

	peerNo := nsi.Nms.GetNodeCount()
	latencyResponse := make([]LatencyResponse, peerNo)
	for i := 0; i < peerNo; i++ {
		var latOut bytes.Buffer
		ip := nsi.Nms.GetNodeDetails(i).IP
		latencyResponse[i].EnodeID = nsi.Nms.GetNodeDetails(i).Enode
		command := fmt.Sprint("ping -c 4 ", ip, " |  awk -F'/' '{ print $5 }' | tail -1")
		cmd := exec.Command("bash", "-c", command)
		cmd.Stdout = &latOut
		err := cmd.Run()
		if err != nil {
			fmt.Println(err)
		}
		latencyString := strings.TrimSuffix(latOut.String(), "\n")
		latency, err := strconv.ParseFloat(latencyString, 10)
		latency = latency * 1000
		latencyStr := strconv.FormatFloat(latency, 'f', 0, 64)
		latencyResponse[i].Latency = latencyStr
	}
	return latencyResponse
}

func (nsi *NodeServiceImpl) transactionSearchDetails(txno string, url string) BlockDetailsResponse {
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	txGetClient := ethClient.GetTransactionReceipt(txno)
	blockNumber := util.HexStringtoInt64(txGetClient.BlockNumber)
	blockDetailsResponse := nsi.getBlockInfo(blockNumber, url)
	return blockDetailsResponse
}

//@TODO: Implement logrotate command to do this.
func (nsi *NodeServiceImpl) LogRotaterGeth() {
	command := "cat $(ls | grep log | grep -v _) > Geth_$(date| sed -e 's/ /_/g')"

	command1 := "echo -en '' > $(ls | grep log | grep -v _)"

	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = "/home/node/qdata/gethLogs"
	err := cmd.Run()
	if err != nil {
		fmt.Println(err)
	}

	cmd1 := exec.Command("bash", "-c", command1)
	cmd1.Dir = "/home/node/qdata/gethLogs"
	err1 := cmd1.Run()
	if err1 != nil {
		fmt.Println(err)
	}

}

func (nsi *NodeServiceImpl) LogRotaterConst() {

	command := "cat $(ls | grep log | grep _) > Constellation_$(date| sed -e 's/ /_/g')"

	command1 := "echo -en '' > $(ls | grep log | grep _)"

	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = "/home/node/qdata/constellationLogs"
	err := cmd.Run()
	if err != nil {
		fmt.Println(err)
	}

	cmd1 := exec.Command("bash", "-c", command1)
	cmd1.Dir = "/home/node/qdata/constellationLogs"
	err1 := cmd1.Run()
	if err1 != nil {
		fmt.Println(err)
	}

}

func (nsi *NodeServiceImpl) RegisterNodeDetails(url string) {
	var nodeUrl = url
	var registeredVal string
	exists := util.PropertyExists("REGISTERED", "/home/setup.conf")
	if exists != "" {
		p := properties.MustLoadFile("/home/setup.conf", properties.UTF8)
		registeredVal = util.MustGetString("REGISTERED", p)
	}
	if registeredVal != "TRUE" {
		ethClient := client.EthClient{nodeUrl}

		enode := ethClient.AdminNodeInfo().ID
		var ipAddr, nodename, pubKey, role string
		existsA := util.PropertyExists("CURRENT_IP", "/home/setup.conf")
		existsB := util.PropertyExists("NODENAME", "/home/setup.conf")
		existsC := util.PropertyExists("PUBKEY", "/home/setup.conf")
		existsD := util.PropertyExists("ROLE", "/home/setup.conf")
		if existsA != "" && existsB != "" && existsC != "" && existsD != "" {
			p := properties.MustLoadFile("/home/setup.conf", properties.UTF8)
			ipAddr = util.MustGetString("CURRENT_IP", p)
			nodename = util.MustGetString("NODENAME", p)
			pubKey = util.MustGetString("PUBKEY", p)
			role = util.MustGetString("ROLE", p)
		}
		registered := fmt.Sprint("REGISTERED=TRUE", "\n")
		util.AppendStringToFile("/home/setup.conf", registered)
		util.DeleteProperty("REGISTERED=", "/home/setup.conf")
		nsi.InitInternalContract(url)
		var tx string

		var timeOutSecs uint = 1
		var maxTimeOutSesc uint = 24 * 60 * 60 // 24 hours
		for tx == "" {
			time.Sleep(time.Duration(timeOutSecs * 1000000000 /* nanoseconds*/))
			tx = nsi.Nms.RegisterNode(nodename, role, pubKey, enode, ipAddr)

			if timeOutSecs > maxTimeOutSesc {
				log.Fatal("Unable to register node after ", maxTimeOutSesc, " seconds")
			}
			timeOutSecs *= 2
		}

		log.Info("Node registered on Network Manager contract")
	}
}

func (nsi *NodeServiceImpl) NetworkManagerContractDeployer(url string) {
	var contractAdd string
	exists := util.PropertyExists("CONTRACT_ADD", "/home/setup.conf")
	if exists != "" {
		p := properties.MustLoadFile("/home/setup.conf", properties.UTF8)
		contractAdd = util.MustGetString("CONTRACT_ADD", p)
	}
	if contractAdd == "" {
		log.Info("Deploying Network Manager Contract")
		filename := []string{"NetworkManagerContract.sol"}
		deployedContract := nsi.deployContract(nil, filename, false, url)
		contAdd := deployedContract[0].ContractAddress
		contAddAppend := fmt.Sprint("CONTRACT_ADD=", contAdd, "\n")
		util.AppendStringToFile("/home/setup.conf", contAddAppend)
		util.DeleteProperty("CONTRACT_ADD=", "/home/setup.conf")

		// Wait after deploying internal SC and before calling it again(registering node) so
		// the second tx does not get rejected on the node level because of validator free allowed tx limit
		time.Sleep(5 * time.Second)
	}
	nsi.InitInternalContract(url)
}

func ConvertToReadable(p client.TransactionDetailsResponse, pending bool, hash bool) TransactionDetailsResponse {
	var readableTransactionDetailsResponse TransactionDetailsResponse

	readableTransactionDetailsResponse.BlockNumber = util.HexStringtoInt64(p.BlockNumber)
	readableTransactionDetailsResponse.Gas = util.HexStringtoInt64(p.Gas)
	readableTransactionDetailsResponse.GasPrice = util.HexStringtoInt64(p.GasPrice)
	readableTransactionDetailsResponse.TransactionIndex = util.HexStringtoInt64(p.TransactionIndex)
	readableTransactionDetailsResponse.Value = util.HexStringtoInt64(p.Value)
	readableTransactionDetailsResponse.Nonce = util.HexStringtoInt64(p.Nonce)
	readableTransactionDetailsResponse.BlockHash = p.BlockHash
	readableTransactionDetailsResponse.From = p.From
	readableTransactionDetailsResponse.Hash = p.Hash
	readableTransactionDetailsResponse.Input = p.Input
	readableTransactionDetailsResponse.To = p.To
	readableTransactionDetailsResponse.V = p.V
	readableTransactionDetailsResponse.R = p.R
	readableTransactionDetailsResponse.S = p.S
	if util.HexStringtoInt64(p.V) == 37 || util.HexStringtoInt64(p.V) == 38 {
		if pending {
			readableTransactionDetailsResponse.TransactionType = "Private or Hash Only"
		} else if hash {
			readableTransactionDetailsResponse.TransactionType = "Hash Only"
		} else {
			readableTransactionDetailsResponse.TransactionType = "Private"
		}

	} else {
		readableTransactionDetailsResponse.TransactionType = "Public"
	}

	return readableTransactionDetailsResponse
}

func (nsi *NodeServiceImpl) CheckGethStatus(url string) bool {
	ethClient := client.EthClient{url}
	var coinbase string
	for coinbase == "" {
		time.Sleep(1 * time.Second)
		coinbase = ethClient.Coinbase()
	}
	return true
}

func (nsi *NodeServiceImpl) GetChartData(url string) []ChartInfo {
	ethClient := client.EthClient{url}
	chartResponse := make([]ChartInfo, chartSize)
	currentTimeRaw := time.Now().Unix()
	currentTime := currentTimeRaw - (currentTimeRaw % 60)
	startTime := currentTime
	currentBlockNumber := util.HexStringtoInt64(ethClient.BlockNumber())
	bucketTime := currentTime - 60
	stopTime := currentTime - int64(60*chartSize)
	i := 0
	lastBlockNoHex := strconv.FormatInt(currentBlockNumber, 16)
	lastBNoHex := fmt.Sprint("0x", lastBlockNoHex)
	blockResponseClient := ethClient.GetBlockByNumber(lastBNoHex)
	lastCreationTime := util.HexStringtoInt64(blockResponseClient.Timestamp)
	lastCreationTimeSec := lastCreationTime - (lastCreationTime % 60)
	if lastCreationTimeSec > stopTime {
		for currentTime > stopTime {
			blockCount := 0
			txnCount := 0
			for currentTime > bucketTime {
				blockNoHex := strconv.FormatInt(currentBlockNumber, 16)
				bNoHex := fmt.Sprint("0x", blockNoHex)
				blockResponseClient := ethClient.GetBlockByNumber(bNoHex)
				creationTimeRaw := util.HexStringtoInt64(blockResponseClient.Timestamp)
				currentTime = creationTimeRaw - (creationTimeRaw % 60)
				if currentTime > bucketTime {
					currentBlockNumber = currentBlockNumber - 1
					txnCount = txnCount + len(blockResponseClient.Transactions)
					blockCount++
				}
			}
			chartResponse[i].BlockCount = blockCount
			chartResponse[i].TransactionCount = txnCount
			chartResponse[i].TimeStamp = (int(bucketTime) + 60) * 1000
			bucketTime = bucketTime - 60
			i++
		}
	}
	for i := 0; i < chartSize; i++ {

		if chartResponse[i].TimeStamp == 0 {
			chartResponse[i].TimeStamp = int(startTime) * 1000
		}
		startTime = startTime - 60
	}
	for i := 0; i < len(chartResponse)/2; i++ {
		j := len(chartResponse) - i - 1
		chartResponse[i], chartResponse[j] = chartResponse[j], chartResponse[i]
	}

	return chartResponse
}

func (nsi *NodeServiceImpl) ContractCrawler(url string) {
	ticker := time.NewTicker(15 * time.Second)
	go func() {
		for range ticker.C {
			if contractCrawlerMutex == 0 {
				nsi.getContracts(url)
			}
		}
	}()
}

func (nsi *NodeServiceImpl) getContracts(url string) {
	contractCrawlerMutex = 1
	ethClient := client.EthClient{url}
	blockNumber := int(util.HexStringtoInt64(ethClient.BlockNumber()))
	for i := lastCrawledBlock + 1; i <= blockNumber; i++ {
		blockNoHex := strconv.FormatInt(int64(i), 16)
		bNoHex := fmt.Sprint("0x", blockNoHex)
		blockResponseClient := ethClient.GetBlockByNumber(bNoHex)
		for _, clientTransactions := range blockResponseClient.Transactions {
			txGetClient := ethClient.GetTransactionReceipt(clientTransactions.Hash)
			if txGetClient.ContractAddress != "" {
				if abiMap[txGetClient.ContractAddress] == "" {
					abiMap[txGetClient.ContractAddress] = "missing"
				}

				if util.HexStringtoInt64(clientTransactions.V) == 37 || util.HexStringtoInt64(clientTransactions.V) == 38 {
					private := ethClient.GetQuorumPayload(clientTransactions.Input)
					if private == "0x" {
						contTypeMap[txGetClient.ContractAddress] = "Hash Only"
					} else {
						contTypeMap[txGetClient.ContractAddress] = "Private"
					}
				}
				contSenderMap[txGetClient.ContractAddress] = clientTransactions.From
				contTimeMap[txGetClient.ContractAddress] = strconv.Itoa(int(util.HexStringtoInt64(blockResponseClient.Timestamp)))
			}
		}
	}
	lastCrawledBlock = blockNumber
	contractCrawlerMutex = 0
}

func (nsi *NodeServiceImpl) ContractList() []ContractTableRow {
	contractList := make([]ContractTableRow, len(abiMap))
	i := 0
	for key := range abiMap {
		contractList[i].ContractAdd = key
		contractList[i].ABIContent = abiMap[key]
		if abiMap[key] == "missing" {
			contractList[i].ABIContent = ""
		}
		contractList[i].ContractName = contNameMap[key]
		contractList[i].ContractType = contTypeMap[key]
		contractList[i].Sender = contSenderMap[key]
		contractList[i].Timestamp = contTimeMap[key]
		contractList[i].Description = contDescriptionMap[key]
		i++
	}

	return contractList
}

func (nsi *NodeServiceImpl) ContractCount() ContractCounter {
	availableABIs := 0
	totalContracts := 0
	for key := range abiMap {
		if abiMap[key] != "missing" {
			availableABIs++
		}
		totalContracts++
	}
	var contractCount ContractCounter
	contractCount.TotalContracts = totalContracts
	contractCount.ABIavailable = availableABIs
	return contractCount
}

func (nsi *NodeServiceImpl) updateContractDetails(contractAddress string, contractName string, abi string, description string) SuccessResponse {
	var successResponse SuccessResponse
	contNameMap[contractAddress] = contractName
	abiMap[contractAddress] = abi
	contDescriptionMap[contractAddress] = description
	successResponse.Status = "Successfully updated contract details"
	return successResponse
}

func (nsi *NodeServiceImpl) ABICrawler(url string) {
	updateLastCheckedTime("0")
	ticker := time.NewTicker(15 * time.Second)
	go func() {
		for range ticker.C {
			if abiCrawlerMutex == 0 {
				nsi.DirectoryCrawl()
			}
		}
	}()
}

func (nsi *NodeServiceImpl) DirectoryCrawl() {
	abiCrawlerMutex = 1
	ABIList := getFilesFromDirectory("/root/lition-maker/contracts")
	nsi.populateABIMap(ABIList)
	abiCrawlerMutex = 0
	updateLastCheckedTime(strconv.Itoa(int(time.Now().Unix())))
}

func getFilesFromDirectory(searchDir string) []CrawledABI {
	fileList := []string{}
	err := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		fileList = append(fileList, path)
		return nil
	})
	if err != nil {
		fmt.Println()
	}
	for _, file := range fileList {
		crawledABIs = append(crawledABIs, getABIsFromDirectory(file)...)
	}
	return crawledABIs
}

func getABIsFromDirectory(searchDir string) []CrawledABI {
	r := regexp.MustCompile(`.json$`)
	var crawledABIs []CrawledABI
	files, _ := ioutil.ReadDir(searchDir)
	for _, file := range files {
		var crawledABI CrawledABI
		if r.MatchString(file.Name()) && !file.IsDir() {
			crawledABI.Filename = searchDir + "/" + file.Name()
			crawledABI.Contractname = file.Name()
			crawledABI.ModificationTime = file.ModTime().Unix()
			if crawledABI.ModificationTime < getLastCheckedTime() {
				continue
			}
			crawledABIs = append(crawledABIs, crawledABI)
		}
	}
	return crawledABIs
}

func (nsi *NodeServiceImpl) populateABIMap(jsons []CrawledABI) {
	for _, file := range jsons {
		if !file.Processed {
			nsi.parseABIJson(file)
			file.Processed = true
		}
	}
}

func (nsi *NodeServiceImpl) parseABIJson(file CrawledABI) {
	var contractJSONContent contractJSONTruffle
	fileBytes, err := ioutil.ReadFile(file.Filename)
	if err != nil {
		log.Println(err)
	}
	jsonContent := string(fileBytes)
	jsonContent = strings.Replace(jsonContent, "\n", "", -1)
	json.Unmarshal([]byte(jsonContent), &contractJSONContent)
	abiContent, _ := json.Marshal(contractJSONContent.Abi)
	abiString := make([]string, len(abiContent))
	for i := 0; i < len(abiContent); i++ {
		abiString[i] = string(abiContent[i])
	}
	abiData := fmt.Sprint(strings.Join(abiString, ""))

	interfaceContent, _ := json.Marshal(contractJSONContent.Interface)
	interfaceString := make([]string, len(interfaceContent))
	for i := 0; i < len(interfaceContent); i++ {
		interfaceString[i] = string(interfaceContent[i])
	}
	interfaceData := fmt.Sprint(strings.Join(interfaceString, ""))
	bytecodeData := contractJSONContent.Bytecode
	contractName := contractJSONContent.ContractName
	var data string
	if len(abiData) != 4 {
		data = abiData
	} else if len(interfaceData) != 4 {
		data = interfaceData
	} else {
		data = jsonContent
		data = strings.Replace(data, "\n", "", -1)
	}
	filename := file.Filename
	command := fmt.Sprint("grep  \"\\\"address\\\":\" ", filename, " | awk -F \\\" '{print $4}'")
	out, _ := exec.Command("bash", "-c", command).Output()
	contractAddress := string(out)
	contractAddress = strings.Replace(contractAddress, "\n", "", -1)
	if contractAddress != "" && contractName != "" {
		nsi.writeContractDetailsToDisk(data, bytecodeData, contractAddress, contractName)
		nsi.updateContractDetails(contractAddress, contractName, data, "default")
	} else if contractAddress != "" && contractName == "" {
		contNameMap[contractAddress] = file.Contractname
		abiMap[contractAddress] = data
		contDescriptionMap[contractAddress] = "default"
	}
}

func (nsi *NodeServiceImpl) writeContractDetailsToDisk(data string, bytecodeData string, contractAddress string, contractName string) {
	jsonString := util.ComposeJSON(data, bytecodeData, contractAddress)
	path := "./contracts"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.Mkdir(path, 0775)
	}
	path = "./contracts/" + contractAddress + "_" + contractName

	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.Mkdir(path, 0775)
	}

	filePath := path + "/" + contractName + ".json"
	jsByte := []byte(jsonString)
	err := ioutil.WriteFile(filePath, jsByte, 0775)
	if err != nil {
		fmt.Println(err)
	}
}

func getLastCheckedTime() int64 {
	fileBytes, err := ioutil.ReadFile("/root/lition-maker/contracts/.lastCheckedTime")
	if err != nil {
		log.Println(err)
	}
	jsonContent := string(fileBytes)
	jsonContent = strings.Replace(jsonContent, "\n", "", -1)
	lastChecked, err := strconv.Atoi(jsonContent)
	return int64(lastChecked)
}

func updateLastCheckedTime(timeVal string) {
	util.DeleteFile("/root/lition-maker/contracts/.lastCheckedTime")
	util.CreateFile("/root/lition-maker/contracts/.lastCheckedTime")
	util.WriteFile("/root/lition-maker/contracts/.lastCheckedTime", timeVal)
}

func (nsi *NodeServiceImpl) createAccount(password string, url string) SuccessResponse {
	var accountDetail SuccessResponse
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	accountAddress := ethClient.CreateAccount(password)
	accountDetail.Status = fmt.Sprint("Account ", accountAddress, " has been created successfully")
	return accountDetail
}

func (nsi *NodeServiceImpl) getAccounts(url string) []ethAccount {
	var accountList []ethAccount
	var nodeUrl = url
	ethClient := client.EthClient{nodeUrl}
	coinbase := ethClient.Coinbase()
	accounts := ethClient.GetAccounts()
	for _, accountID := range accounts {
		var account ethAccount
		account.AccountAddress = accountID
		if accountID == coinbase {
			account.Coinbase = true
		}
		account.Balance = util.HexStringtoLargeInt64(ethClient.GetBalance(accountID))
		accountList = append(accountList, account)
	}
	return accountList
}

func (nsi *NodeServiceImpl) getNodeIPs(url string) []connectedIP {
	var nodeUrl = url
	var ipList []connectedIP
	var connectedIPs = map[string]int{}
	ethClient := client.EthClient{nodeUrl}
	enode := ethClient.AdminNodeInfo().ID
	nsi.InitInternalContract(url)
	nodeList := nsi.Nms.GetNodeDetailsList()
	for _, node := range nodeList {
		if node.Enode != enode {
			count := connectedIPs[node.IP]
			connectedIPs[node.IP] = count + 1
		}
	}
	for k := range connectedIPs {
		var connected connectedIP
		connected.IP = k
		connected.Count = connectedIPs[k]
		ipList = append(ipList, connected)
	}
	return ipList
}

func (nsi *NodeServiceImpl) InitInternalContract(url string) {

	if nsi.Nms.Ic == nil {
		var contractAdd string
		exists := util.PropertyExists("CONTRACT_ADD", "/home/setup.conf")
		if exists != "" {
			p := properties.MustLoadFile("/home/setup.conf", properties.UTF8)
			contractAdd = util.MustGetString("CONTRACT_ADD", p)
		}

		if len(contractAdd) < 1 {
			log.Error("InitInternalContract empty contract address")
			return
		}

		eth, err := ethclient.Dial(url)
		if err != nil {
			log.Error("InitInternalContract ", err)
		}

		lition, err := internalContract.NewScClient(common.HexToAddress(contractAdd), eth)
		if err != nil {
			log.Error("internalContract.NewPowerChain ", err)
		}
		log.Info("InitInternalContract address: ", contractAdd)

		nsi.Nms.Ic = lition
	}
}

// This wrapper is used in event listener for automatic voting
func (nsi *NodeServiceImpl) ProposeValidator(event *litionScClient.PowerChainScClientAccountMining) {
	validatorAddress := event.Account.String()
	voteFlag := event.Mining
	log.Info("Aut. ProposeValidator function invoked. Validator: ", validatorAddress, ", vote flag: ", voteFlag)
	nsi.ethProposeValidator(nsi.Url, validatorAddress, voteFlag)

	if validatorAddress == nsi.NodeAccAddress && nsi.MiningRegistered == false {
		close(nsi.MiningRegisteredChan)
		nsi.MiningRegistered = true
	}
}

func (nsi *NodeServiceImpl) UpdateLastMainnetNotary(event *litionScClient.PowerChainScClientNotary) {
	log.Info("New Mainnet Notary. LastProccesedBlock: ", event.LastBlock.Uint64(), ", blocksProcessedCount: ", event.BlocksProcessed.Int64())
	nsi.LastPowerChainScNotaryBlock = event.LastBlock.Int64()
}

func (nsi *NodeServiceImpl) UnvoteValidatorInternal(validatorAddress string) {
	log.Info("UnvoteValidator(itself) function invoked. Validator: ", validatorAddress)
	nsi.ethProposeValidator(nsi.Url, validatorAddress, false)
}

func byte32(s []byte) (a *[32]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
}

func printHex(b []byte) {
	dst := make([]byte, hex.EncodedLen(len(b)))

	hex.Encode(dst, b)
	fmt.Printf("\"0x%s\",", dst)
}

func logDebugNotaryData(actBlock int64, startBlock int64, endBlock int64) {
	log.Debug("Notary Debug: BC actBlock: ", actBlock, ", notaryStartBlock: ", startBlock, ", notaryEndBlock: ", endBlock)
}

func (nsi *NodeServiceImpl) Notary(privateKey *ecdsa.PrivateKey) {
	ethClient := client.EthClient{nsi.Url}

	iAmValidator := false
	for _, bftValidator := range ethClient.GetValidators(ethClient.BlockNumber()) {
		if nsi.NodeAccAddress == bftValidator.String() {
			iAmValidator = true
		}
	}

	actblockNumber := util.HexStringtoInt64(ethClient.BlockNumber())

	if iAmValidator == false {
		log.Warn("As of block: ", actblockNumber, " you are not registred as validator on geth level. Please control this by attaching to the rpc port of your node and call istanbul.GetValidators(). ",
			"In case your node is running for mote than 10 minutes and you are not voted as validator, please call StartMining on PowerChain SicechainManger here: https://www.lition.io/sidechainmanager/ ",
			"and you will be automatically voted as validator by other nodes.")
		return
	}

	// Check every 30 minutes if there is different last notary block based on GetChainDynamicDetails() getter
	// vs nsi.LastPowerChainScNotaryBlock which is updated by listener, if it is different, listener probably stopped working
	nsi.NotaryInvokedCounter++
	if nsi.NotaryInvokedCounter%30 == 0 {
		nsi.NotaryInvokedCounter = 0

		chainDynamicDetails, err := nsi.PowerChainContractClient.GetChainDynamicDetails()
		if err == nil {
			if chainDynamicDetails.LastNotaryBlock.Int64() > nsi.LastPowerChainScNotaryBlock {

				log.Warn("Last notary block based on GetChainDynamicDetails() getter is bigger than the one, which is updated by listener (listener propably stopped working")
				nsi.LastPowerChainScNotaryBlock = chainDynamicDetails.LastNotaryBlock.Int64()
			}
		} else {
			log.Error("Unable to check LastMainnetNotaryBlock based on GetChainDynamicDetails(). Err: ", err)
		}
	}

	if nsi.LastInternalNotary < nsi.LastPowerChainScNotaryBlock {
		nsi.LastInternalNotary = nsi.LastPowerChainScNotaryBlock
	}

	multiplier := (actblockNumber - nsi.LastPowerChainScNotaryBlock) / nsi.NotaryPeriod

	notaryEndBlock := nsi.LastPowerChainScNotaryBlock + nsi.NotaryPeriod*multiplier
	notaryEndBlockHex := fmt.Sprint("0x", strconv.FormatInt(notaryEndBlock, 16))

	// Do not process notary if there is not enough blocks since the last processed notary
	if nsi.LastProcessedNotaryBlock >= notaryEndBlock {
		return
	}

	if actblockNumber < notaryEndBlock {
		return
	}

	//// Internal SC part ////
	stats := ethClient.GetStatistics(fmt.Sprint("0x", strconv.FormatInt(nsi.LastPowerChainScNotaryBlock+1, 16)), notaryEndBlockHex)

	// No transactions present, do no call notary
	if len(stats.Users) == 0 {
		// Show debug message only every 20 minutes
		if nsi.NotaryInvokedCounter%20 == 0 {
			log.Debug("Notary periodic check: Users consumptions from node statistics is empty")
			logDebugNotaryData(actblockNumber, nsi.LastPowerChainScNotaryBlock+1, notaryEndBlock)
		}
		return
	}

	// No miners present, do no call notary
	if len(stats.Validators) == 0 {
		// Show debug message only every 20 minutes
		if nsi.NotaryInvokedCounter%20 == 0 {
			log.Debug("Notary periodic check: Miners from node statistics is empty")
			logDebugNotaryData(actblockNumber, nsi.LastPowerChainScNotaryBlock+1, notaryEndBlock)
		}
		return
	}

	// Invalid max gas provided
	if stats.MaxGas == 0 {
		// Show debug message only every 20 minutes
		if nsi.NotaryInvokedCounter%20 == 0 {
			log.Debug("Notary periodic check: MaxGas from node statistics == 0")
			logDebugNotaryData(actblockNumber, nsi.LastPowerChainScNotaryBlock+1, notaryEndBlock)
		}
		return
	}

	if nsi.LastInternalNotary < notaryEndBlock {
		hashToSign, err := nsi.Nms.GetSignatureHashFromNotary(notaryEndBlock, stats.Validators, stats.BlocksMined, stats.Users, stats.GasConsumptions, stats.MaxGas)
		if err != nil {
			log.Error("Notary GetSignatureHashFromNotary err: ", err)
			logDebugNotaryData(actblockNumber, nsi.LastPowerChainScNotaryBlock+1, notaryEndBlock)
			return
		}

		signature, err := crypto.Sign(hashToSign[:], privateKey)
		if err != nil {
			log.Error("Notary crypto.Sign(hashToSign[:], privateKey) err: ", err)
			logDebugNotaryData(actblockNumber, nsi.LastPowerChainScNotaryBlock+1, notaryEndBlock)
			return
		}

		_, err = nsi.Nms.StoreSignature(notaryEndBlock, contractclient.Signature{uint8(int(signature[64])) + 27, *byte32(signature[:32]), *byte32(signature[32:64])})
		if err != nil {
			log.Error("Notary StoreSignature err: ", err)
			logDebugNotaryData(actblockNumber, nsi.LastPowerChainScNotaryBlock+1, notaryEndBlock)
			return
		}

		nsi.LastInternalNotary = notaryEndBlock
	}

	validators := ethClient.GetValidators(notaryEndBlockHex)
	if len(validators) < 1 {
		log.Error("Notary periodic check: there are no validators on node level")
		logDebugNotaryData(actblockNumber, nsi.LastPowerChainScNotaryBlock+1, notaryEndBlock)
		return
	}

	//// External SC part ////
	if validators[int(notaryEndBlock/nsi.NotaryPeriod)%len(validators)] == crypto.PubkeyToAddress(privateKey.PublicKey) {
		nodeRequired := len(validators)
		// if there is less or same number of nodes required by BFT (4), then you need all signatures
		if nodeRequired > 4 {
			nodeRequired = 2/3*nodeRequired + 1
		}

		sigCountBigInt, err := nsi.Nms.GetSignaturesCount(notaryEndBlock)
		if err != nil {
			log.Error("Notary GetSignaturesCount err: ", err)
			logDebugNotaryData(actblockNumber, nsi.LastPowerChainScNotaryBlock+1, notaryEndBlock)
			return
		}
		sigCount := int(sigCountBigInt.Int64())

		if (sigCount >= nodeRequired) && nsi.LastProcessedNotaryBlock != notaryEndBlock {
			v := make([]uint8, 0, sigCount)
			s := make([][32]byte, 0, sigCount)
			r := make([][32]byte, 0, sigCount)
			for i := 0; i < sigCount; i++ {
				sig, err := nsi.Nms.GetSignatures(notaryEndBlock, i)
				if err != nil {
					log.Error("Notary GetSignaturesCount err: ", err)
					logDebugNotaryData(actblockNumber, nsi.LastPowerChainScNotaryBlock+1, notaryEndBlock)
					continue
				}

				v = append(v, sig.V)
				s = append(s, sig.S)
				r = append(r, sig.R)
			}

			tx, err := nsi.PowerChainContractClient.Notary(bind.NewKeyedTransactor(privateKey), new(big.Int).SetInt64(nsi.LastPowerChainScNotaryBlock+1), new(big.Int).SetInt64(notaryEndBlock),
				stats.Validators, stats.BlocksMined, stats.Users, stats.GasConsumptions, stats.MaxGas, v, r, s)
			if err == nil {
				log.Info("Notary successfully sent, tx Hash: ", tx.Hash().String())

				nsi.LastProcessedNotaryBlock = notaryEndBlock
			} else {
				//reset notary in case of error (maybe not enough staking)
				nsi.LastProcessedNotaryBlock = nsi.LastPowerChainScNotaryBlock

				log.Error("Notary failed: ", err)
				logDebugNotaryData(actblockNumber, nsi.LastPowerChainScNotaryBlock+1, notaryEndBlock)

				// Prints notary data
				log.Info("Sent Data: ")

				var minersData string = "["
				var blocksData string = "["
				for index, statsMiner := range stats.Validators {
					minersData += "\"" + statsMiner.String() + "\","
					blocksData += strconv.FormatInt(int64(stats.BlocksMined[index]), 10) + ","
				}
				minersData += "]"
				blocksData += "]"

				var usersData string = "["
				var gasData string = "["
				for index, statsUser := range stats.Users {
					usersData += "\"" + statsUser.String() + "\","
					gasData += strconv.FormatInt(int64(stats.GasConsumptions[index]), 10) + ","
				}
				usersData += "]"
				gasData += "]"

				sentData := "StartBlock:\n" + strconv.FormatInt(nsi.LastPowerChainScNotaryBlock+1, 10) + "\n" +
					"EndBlock:\n" + strconv.FormatInt(notaryEndBlock, 10) + "\n" +
					"Miners:\n" + minersData + "\n" +
					"BlocksMined:\n" + blocksData + "\n" +
					"Users:\n" + usersData + "\n" +
					"GasCOnsumptions:\n" + gasData + "\n" +
					"LargestTx:\n" + strconv.FormatInt(int64(stats.MaxGas), 10) + "\n"
				fmt.Printf(sentData)

				fmt.Printf("v\n")
				for _, vGet := range v {
					fmt.Printf(strconv.Itoa(int(vGet)))
					fmt.Printf(", ")
				}

				fmt.Printf("r\n")
				for _, rGet := range r {
					printHex(rGet[:])
				}

				fmt.Printf("\ns\n")
				for _, sGet := range s {
					printHex(sGet[:])
				}
				fmt.Printf("\n\n")
			}
		}
	}
}
