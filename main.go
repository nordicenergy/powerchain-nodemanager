package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"gitlab.com/nordicenergy/powerchain-maker-nodemanager/client"
	"gitlab.com/nordicenergy/powerchain-maker-nodemanager/contractclient"
	"gitlab.com/nordicenergy/powerchain-maker-nodemanager/service"
	"gitlab.com/nordicenergy/nordicenergy/accounts/abi/bind"
	"gitlab.com/nordicenergy/nordicenergy/crypto"
	nordicenergyScClient "gitlab.com/nordicenergy/nordicenergy_contracts/contracts/client"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
}

func main() {
	nodeUrl := flag.String("nodeUrl", "http://localhost:22000", "Node url")
	listenPort := flag.Int("listenPort", 8000, "Listening Port")
	infuraURL := flag.String("infuraURL", "", "Infura URL, which connects to the ethereum network (e.g. wss://ropsten.infura.io/ws)")
	contractAddress := flag.String("contractAddress", "", "PowerChain contract address")
	privateKeyStr := flag.String("privateKey", "", "Private Key for mining (Must be valid ethereum key)")
	chainID := flag.Int("chainID", 0, "Chain ID of the sidechain registered in PowerChain contract to connect to")
	miningFlag := flag.Bool("miningFlag", false, "Flag if nodemanager is running on top of geth, which is also mining")
	flag.Parse()

	listenPortStr := ":" + strconv.Itoa(*listenPort)
	// Init PowerChain contract client
	contractClient, auth, pubKey, err := InitPowerChainContractClient(*infuraURL, *contractAddress, *chainID, *privateKeyStr, *miningFlag)
	if err != nil {
		log.Fatal("PowerChain contract client initialization failed. Err: ", err)
	}

	router := mux.NewRouter()
	nodeService, err := service.NewNodeServiceImpl(*nodeUrl, contractClient, pubKey, &contractclient.NetworkMapContractClient{client.EthClient{*nodeUrl}, auth, nil})
	if err != nil {
		log.Fatal("NewNodeServiceImpl init failed. Error: ", err)
	}

	ticker := time.NewTicker(86400 * time.Second)
	go func() {
		for range ticker.C {
			log.Debug("Rotating log for Geth and Constellation.")
			nodeService.LogRotaterGeth()
			nodeService.LogRotaterConst()
		}
	}()

	go func() {
		nodeService.CheckGethStatus(*nodeUrl)
		log.Info("Geth is running")

		if *miningFlag == true {
			// Start standalone event listeners
			go contractClient.Start_accMiningEventListener(nodeService.ProposeValidator)
			go contractClient.Start_notaryEventListener(nodeService.UpdateLastMainnetNotary)

			userDetails, err := contractClient.GetUserDetails(pubKey)
			if err != nil {
				log.Fatal("Unable to call GetUserDetails on SC. Err: ", err)
			}

			if userDetails.Mining == false {
				// Let nordicenergy SC know that this node wants to start mining
				tx, err := contractClient.StartMining(auth)
				if err != nil {
					log.Fatal("Unable to start mining. Err: ", err)
				}
				log.Info("StartMining tx sent")

				ethScanURL := ""
				if strings.Contains(*infuraURL, "ropsten") == true {
					ethScanURL = "https://ropsten.etherscan.io/tx/" + tx.Hash().String()
				} else {
					ethScanURL = "https://etherscan.io/tx/" + tx.Hash().String()
				}

				nodeService.MiningRegistered = false
				nodeService.MiningRegisteredChan = make(chan struct{})

				terminalMsg :=
					"\n*****************************************************************************\n" +
						"**** Waiting for StartMinig to be registered in PowerChain Smart Contract... ****\n" +
						"*****************************************************************************\n\n" +

						"It might take from few seconds to few hours(edge case when ethereum network is halted). " +
						"You can check status of the StartMining transaction here:\n" + ethScanURL + "\n\n" +
						"In case it takes too long and you need to speed up things, you can manually call StartMining method with " +
						"higher gas price through our SideChain Manager here:\nhttps://nordicenergy.io/sidechainmanager\n\n" +
						"Do not shut down this process in the meantime.\n\n" +
						"*****************************************************************************\n\n"
				fmt.Printf(terminalMsg)

				// Wait for StartMining to be processed so user can register his node without being rejected by nodes
				// Validators can send free tx only once per 5 seconds and they must be registered in SC as active validators
				<-nodeService.MiningRegisteredChan

				// Wait a few seconds so nodes register this account as active validator and do not reject it's internal SC transactions
				time.Sleep(5 * time.Second)
				log.Info("StartMining successfully registered")
			}
		}

		nodeService.NetworkManagerContractDeployer(*nodeUrl)
		nodeService.RegisterNodeDetails(*nodeUrl)
		nodeService.ContractCrawler(*nodeUrl)
		nodeService.ABICrawler(*nodeUrl)

		if *miningFlag == true {
			notaryTicker := time.NewTicker(60 * time.Second)
			go func() {
				privateKey, err := crypto.HexToECDSA(*privateKeyStr)
				if err != nil {
					log.Fatal("Unable to process provided private key")
				}
				for range notaryTicker.C {
					nodeService.Notary(privateKey)
				}
			}()
		}

		log.Info("Node is running")
	}()

	router.HandleFunc("/txn/{txn_hash}", nodeService.GetTransactionInfoHandler).Methods("GET")
	router.HandleFunc("/txn", nodeService.GetLatestTransactionInfoHandler).Methods("GET")
	router.HandleFunc("/block/{block_no}", nodeService.GetBlockInfoHandler).Methods("GET")
	router.HandleFunc("/block", nodeService.GetLatestBlockInfoHandler).Methods("GET")
	router.HandleFunc("/genesis", nodeService.GetGenesisHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/peer/{peer_id}", nodeService.GetOtherPeerHandler).Methods("GET")
	router.HandleFunc("/peer", nodeService.GetCurrentNodeHandler).Methods("GET")
	router.HandleFunc("/nmcAddress", nodeService.GetNmcAddress).Methods("POST")
	router.HandleFunc("/txnrcpt/{txn_hash}", nodeService.GetTransactionReceiptHandler).Methods("GET")
	router.HandleFunc("/deployContract", nodeService.DeployContractHandler).Methods("POST")
	router.HandleFunc("/latestBlock", nodeService.LatestBlockHandler).Methods("GET")
	router.HandleFunc("/latency", nodeService.LatencyHandler).Methods("GET")
	router.HandleFunc("/txnsearch/{txn_hash}", nodeService.TransactionSearchHandler).Methods("GET")
	router.HandleFunc("/getNodeDetails/{index}", nodeService.Nms.GetNodeDetailsResponseHandler).Methods("GET")
	router.HandleFunc("/getNodeList", nodeService.Nms.GetNodeListSelfResponseHandler).Methods("GET")
	router.HandleFunc("/activeNodes", nodeService.Nms.ActiveNodesHandler).Methods("GET")
	router.HandleFunc("/chartData", nodeService.GetChartDataHandler).Methods("GET")
	router.HandleFunc("/contractList", nodeService.GetContractListHandler).Methods("GET")
	router.HandleFunc("/contractCount", nodeService.GetContractCountHandler).Methods("GET")
	router.HandleFunc("/updateContractDetails", nodeService.ContractDetailsUpdateHandler).Methods("POST")
	router.HandleFunc("/createAccount", nodeService.CreateAccountHandler).Methods("POST")
	router.HandleFunc("/createAccount", nodeService.OptionsHandler).Methods("OPTIONS")
	router.HandleFunc("/getAccounts", nodeService.GetAccountsHandler).Methods("GET")

	router.PathPrefix("/contracts").Handler(http.StripPrefix("/contracts", http.FileServer(http.Dir("/root/powerchain-maker/contracts"))))
	router.PathPrefix("/geth").Handler(http.StripPrefix("/geth", http.FileServer(http.Dir("/home/node/qdata/gethLogs"))))
	router.PathPrefix("/constellation").Handler(http.StripPrefix("/constellation", http.FileServer(http.Dir("/home/node/qdata/constellationLogs"))))
	router.PathPrefix("/").Handler(http.StripPrefix("/", NewFileServer("NodeManagerUI")))

	log.Info(fmt.Sprintf("Node Manager listening on %s...", listenPortStr))

	srv := &http.Server{
		Handler: router,
		Addr:    "0.0.0.0" + listenPortStr,

		//WriteTimeout: 15 * time.Second,
		//ReadTimeout:  15 * time.Second,
		//IdleTimeout:  time.Second * 60,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	if *miningFlag == true {
		isActiveValidator := true

		userDetails, err := contractClient.GetUserDetails(pubKey)
		if err == nil {
			isActiveValidator = userDetails.Mining
		} else {
			log.Error("Unable to call IsActiveValidator on SC during shutdown. Unvote validator as he was active. Err: ", err)
		}

		if isActiveValidator == true {
			// Unvote itself
			nodeService.UnvoteValidatorInternal(pubKey)

			// Stop mining
			tx, err := contractClient.StopMining(auth)
			if err != nil {
				log.Fatal("Unable to stop mining. Err: ", err)
			}
			log.Info("StoptMining tx sent. Hash: ", tx.Hash().String())
		}
	}

	// Deinit nordicenergy smart contract cliet
	contractClient.DeInit()

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), 15)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	srv.Shutdown(ctx)
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	log.Info("Node Manager Shutting down")
	os.Exit(0)
}

type MyFileServer struct {
	name    string
	handler http.Handler
}

func NewFileServer(file string) *MyFileServer {

	return &MyFileServer{file, http.FileServer(http.Dir(file))}

}
func (mf *MyFileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	_, err := os.Open(mf.name + "/" + r.URL.Path)
	if err != nil {
		r.URL.Path = "/"
	}

	mf.handler.ServeHTTP(w, r)
}

func InitPowerChainContractClient(
	infuraURL string,
	contractAddress string,
	chainID int,
	privateKeyStr string,
	miningFlag bool) (client *nordicenergyScClient.ContractClient, auth *bind.TransactOpts, pubKey string, err error) {

	log.Info("Initialize PowerChain Contract Client")
	err = nil

	if privateKeyStr == "" {
		err = errors.New("NodeManager misconfiguration. Private key must be provided")
		return
	}

	// Init PowerChain Smartcontract client
	client, err = nordicenergyScClient.NewClient(infuraURL, contractAddress, big.NewInt(int64(chainID)))
	if err != nil {
		return
	}

	// Init PowerChain Smartcontract event listeners and auth
	if miningFlag == true {
		err = client.InitAccMiningEventListener()
		if err != nil {
			log.Error("Unable to init 'StartMining' event listeners")
			return
		}

		err = client.InitNotaryEventListener()
		if err != nil {
			log.Error("Unable to init 'Notary' event listeners")
			return
		}
	}

	var privateKey *ecdsa.PrivateKey
	privateKey, err = crypto.HexToECDSA(privateKeyStr)
	if err != nil {
		log.Error("Unable to process provided private key")
		return
	}
	pubKey = crypto.PubkeyToAddress(privateKey.PublicKey).String()
	auth = bind.NewKeyedTransactor(privateKey)

	return
}
