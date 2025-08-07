package main
//TODO faire les fichiers systemd, ajouter numérode version et paramètres -v et -h

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"
	"gopkg.in/yaml.v2"
	"strconv"
)

type BlacklistResponse struct {
	Meta struct {
		GeneratedAt time.Time `json:"generatedAt"`
	} `json:"meta"`
	Data []struct {
		IPAddress            string    `json:"ipAddress"`
		AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
		LastReportedAt       time.Time `json:"lastReportedAt"`
	} `json:"data"`
}

type configYaml struct {
	ApiKey		string `yaml:"apiKey"` 
	ApiEndpoint	string `yaml:"apiEndpoint"`
	NftablesTable	string `yaml:"nftablesTable"`
	Ipv4Set		string `yaml:"ipv4Set"`
	Ipv6Set		string `yaml:"ipv6Set"`
	DayAgedMax	int    `yaml:"dayAgedMax"`
	Limit		int    `yaml:"limit"`
	Categories	string `yaml:"categories"`
}

func (conf *configYaml) Parse(data []byte) error {
    return yaml.Unmarshal(data, conf)
}

var c configYaml

const (
	yamlFile	= "/etc/abuseipdb/abuseipdb.yaml"
)

func loadConfig() {    
	data, err := ioutil.ReadFile(yamlFile)
    	if err != nil {
        	log.Fatal(err)
    	}
	if err := c.Parse(data); err != nil {
        	log.Fatal(err)
		fmt.Println(err)
    	}
}



// Function to fetch the blacklist from AbuseIPDB with category filtering
func fetchBlacklist(categories string) ([]string, []string, error) {
	// Create the HTTP request
	req, err := http.NewRequest("GET", c.ApiEndpoint, nil)
	if err != nil {
		return nil, nil, err
	}

	// Set the Authorization header with your API key
	req.Header.Set("Key", c.ApiKey)
	req.Header.Set("Accept", "application/json")

	// Set category filter in query parameters (e.g., "18,22" for DDoS and Brute Force)
	q := req.URL.Query()
	q.Add("categories", categories)
	q.Add("limit", strconv.Itoa(c.Limit))
	req.URL.RawQuery = q.Encode()

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	// Parse the response JSON
	var response BlacklistResponse
	//optimisation possible utiliser make pour tailler un response.Data suffisament grand
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, nil, err
	}

	// Separate IPs into IPv4 and IPv6
	ipv4Addresses:=make([]string,0,c.Limit)
	ipv6Addresses:=make([]string,0,c.Limit/50)
	afterDay := time.Now().AddDate(0,0,-1 * c.DayAgedMax )
	for _, data := range response.Data {
	 if data.LastReportedAt.After(afterDay) {
		if strings.Contains(data.IPAddress, ":") {
				// It's an IPv6 address
				ipv6Addresses = append(ipv6Addresses, data.IPAddress)
			} else {
				// It's an IPv4 address
				ipv4Addresses = append(ipv4Addresses, data.IPAddress)
			}
		}
	}
	//temporaire pour réglage des tailles des listes d'IP
	println("nb ipv4",len(ipv4Addresses))
	println("nb ipv6",len(ipv6Addresses))

	return ipv4Addresses, ipv6Addresses, nil
}

// Function to initialize the nftables ruleset (create table and chains if necessary)
func initNftables() error {
	// Check if the table exists, if not create it
	cmd := exec.Command("nft", "list", "tables")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil || !strings.Contains(out.String(), c.NftablesTable) {
		// Create table if it doesn't exist
		cmd := exec.Command("nft", "add", "table", c.NftablesTable)
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("error creating table: %v", err)
		}
		fmt.Println("Created nftables table:", c.NftablesTable)
	}

	// Create the base chain if it doesn't exist
	cmd = exec.Command("nft", "list", "chain", c.NftablesTable, "input")
	out.Reset()
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil || !strings.Contains(out.String(), "input") {
		// Create input chain if it doesn't exist
		cmd := exec.Command("nft", "add", "chain", c.NftablesTable, "input", "{ type filter hook input priority 0; }")
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("error creating chain: %v", err)
		}
		fmt.Println("Created nftables chain: input")
	}

	return nil
}

// Function to purge existing sets before adding new IPs
func purgeNftablesSet(setName string) error {
	// Purge the set if it exists
	cmd := exec.Command("nft", "flush", "set", c.NftablesTable, setName)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error flushing nftables set: %v", err)
	}
	fmt.Println("Purged nftables set:", setName)
	return nil
}

// Function to create or update a nftables set
func createNftablesSet(ipAddresses []string, setName string, ipType string) error {
	// Purge the set if it exists
	var out bytes.Buffer
	err := purgeNftablesSet(setName)
	if err != nil {
		// Create the nftables set
		cmd := exec.Command("nft", "add", "set", c.NftablesTable, setName, "{type", ipType,"; flags interval ; auto-merge ; }")
		// ligne déplacée var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("error creating nftables set: %v", err)
		}
		typ := "ip6"
		if setName == c.Ipv4Set {
			typ = "ip"
		}
		//metre le log des rejets en optionnel
		cmd = exec.Command("nft", "add", "rule", c.NftablesTable, "input", typ, "saddr", "@"+setName, "log prefix \"abuseipdb reject:\" drop")
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("error creating rule for set: %v", err)
		}

	}
	// Add the IPs to the set
	//Passer tranche dans les paramètres
	tranche:=5000
	for debut:=0;debut < len(ipAddresses)-1;debut=debut+tranche {
		cmd := exec.Command("nft", "add", "element", c.NftablesTable, setName, fmt.Sprintf("{ %s }", strings.Join(ipAddresses[debut:min(debut+tranche,len(ipAddresses)-1)],",")))
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("error adding IP to nftables set: %v", err)
		}
		fmt.Println(out.String())
	}
	// Print the output from the nft command
	return nil
}

func main() {
	loadConfig()
	// Initialize nftables setup if necessary
	err := initNftables()
	if err != nil {
		log.Fatalf("Error initializing nftables: %v", err)
	}

	// Fetch the blacklist from AbuseIPDB with the given categories
	ipv4Ips, ipv6Ips, err := fetchBlacklist(c.Categories)
	if err != nil {
		log.Fatalf("Error fetching blacklist: %v", err)
	}

	// Check if there are any IPs to block
	if len(ipv4Ips) == 0 && len(ipv6Ips) == 0 {
		log.Println("No IPs found to block.")
		return
	}

	// Create the nftables sets for IPv4 and IPv6
	if len(ipv4Ips) > 0 {
		err = createNftablesSet(ipv4Ips, c.Ipv4Set, "ipv4_addr")
		if err != nil {
			log.Fatalf("Error creating nftables IPv4 set: %v", err)
		}
	}

	if len(ipv6Ips) > 0 {
		err = createNftablesSet(ipv6Ips, c.Ipv6Set, "ipv6_addr")
		if err != nil {
			log.Fatalf("Error creating nftables IPv6 set: %v", err)
		}
	}

	log.Println("Successfully created nftables sets and added IPs.")
}
