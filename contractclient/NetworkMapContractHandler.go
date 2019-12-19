package contractclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"gitlab.com/lition/lition-maker-nodemanager/util"
)

type NodeDetailsSelf struct {
	Name      string `json:"nodeName,omitempty"`
	Role      string `json:"role,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
	Enode     string `json:"enode,omitempty"`
	IP        string `json:"ip,omitempty"`
	Self      string `json:"self,omitempty"`
	Active    string `json:"active,omitempty"`
}

type ActiveNodes struct {
	NodeCount      int `json:"nodeCount,omitempty"`
	TotalNodeCount int `json:"totalNodeCount,omitempty"`
}

type UpdateNode struct {
	NodeName string `json:"nodeName,omitempty"`
	Role     string `json:"role,omitempty"`
}

func (nms *NetworkMapContractClient) UpdateNodeRequestsHandler(w http.ResponseWriter, r *http.Request) {
	var request NodeDetails
	_ = json.NewDecoder(r.Body).Decode(&request)
	enode := request.Enode
	role := util.PropertyExists("ROLE", "/home/setup.conf")
	nodeName := request.Name
	publickey := request.PublicKey
	ip := request.IP

	response := nms.UpdateNode(nodeName, role, publickey, enode, ip)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control")
	json.NewEncoder(w).Encode(response)
}

func (nms *NetworkMapContractClient) GetNodeDetailsResponseHandler(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	index, err := strconv.ParseInt(params["index"], 10, 64)
	i := int(index)
	if err != nil {
		fmt.Println(err)
	}
	response := nms.GetNodeDetails(i)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control")
	json.NewEncoder(w).Encode(response)
}

func (nms *NetworkMapContractClient) GetNodeListResponseHandler(w http.ResponseWriter, r *http.Request) {
	response := nms.GetNodeDetailsList()

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control")
	json.NewEncoder(w).Encode(response)
}

func (nms *NetworkMapContractClient) GetNodeListSelfResponseHandler(w http.ResponseWriter, r *http.Request) {
	enode := nms.EthClient.AdminNodeInfo().ID
	adminPeers := nms.EthClient.AdminPeers()

	var peerEnodes = map[string]bool{}
	for i := 0; i < len(adminPeers); i++ {
		peerEnodes[adminPeers[i].ID] = true
	}
	nodeList := nms.GetNodeDetailsList()
	response := make([]NodeDetailsSelf, len(nodeList))
	for i := 0; i < len(nodeList); i++ {
		response[i].IP = nodeList[i].IP
		response[i].PublicKey = nodeList[i].PublicKey
		response[i].Enode = nodeList[i].Enode
		response[i].Role = nodeList[i].Role
		response[i].Name = nodeList[i].Name
		if nodeList[i].Enode == enode {
			response[i].Self = "true"
			response[i].Active = "true"
		} else {
			response[i].Self = "false"
			if peerEnodes[nodeList[i].Enode] {
				response[i].Active = "true"
			} else {
				response[i].Active = "false"
			}
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control")
	json.NewEncoder(w).Encode(response)
}

func (nms *NetworkMapContractClient) ActiveNodesHandler(w http.ResponseWriter, r *http.Request) {
	adminPeers := nms.EthClient.AdminPeers()
	activeNodes := len(adminPeers) + 1
	contractResponse := nms.GetNodeDetailsList()
	totalNodes := len(contractResponse)
	response := ActiveNodes{activeNodes, totalNodes}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control")
	json.NewEncoder(w).Encode(response)
}

func (nms *NetworkMapContractClient) OptionsHandler(w http.ResponseWriter, r *http.Request) {
	response := "Options Handled"
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control")
	json.NewEncoder(w).Encode(response)
}
