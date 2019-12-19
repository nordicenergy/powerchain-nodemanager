# inetnral-network-contract-abi
#### Prerequisites
##### solc
sudo add-apt-repository ppa:ethereum/ethereum  
sudo apt-get update  
sudo apt-get install solc  

##### abigen
go get -u github.com/ethereum/go-ethereum  
cd $GOPATH/src/github.com/ethereum/go-ethereum/  
make  
make devtools  

#### Create SC ABI
run
```
solc --abi --overwrite --optimize NetworkManagerContract.sol --output-dir contractclient/internalcontract
```

#### Create SC go class 
run
```
abigen --abi=contractclient/internalcontract/NetworkManagerContract.abi --pkg=ScClient --out=contractclient/internalcontract/NetworkManagerContract.go 
// Replace imports in NetworkManagerContract.go from "github.com/ethereum/go-ethereum" to "gitlab.com/lition/lition"
```
