package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Run shell commands and return output as a list of strings
func runCommand(command string, args ...string) []string {
	cmd := exec.Command(command, args...)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[!] Error running %s: %v\n", command, err)
		return nil
	}
	lines := strings.Split(string(output), "\n")
	return lines
}

// Fetch JavaScript URLs using various tools
func extractJSUrls(domain string) []string {
	fmt.Printf("[*] Fetching URLs for %s...\n", domain)

	// Get URLs from multiple sources
	waybackUrls := runCommand("waybackurls", domain)
	gauUrls := runCommand("gau", domain)
	katanaUrls := runCommand("katana", "-u", "https://"+domain, "-jc")

	// Merge results
	allUrls := append(waybackUrls, gauUrls...)
	allUrls = append(allUrls, katanaUrls...)

	// Filter for JavaScript files
	jsRegex := regexp.MustCompile(`(?i)\.js(\?|$)`)
	var jsUrls []string
	seen := make(map[string]bool)

	for _, url := range allUrls {
		if jsRegex.MatchString(url) && !seen[url] {
			jsUrls = append(jsUrls, url)
			seen[url] = true
		}
	}

	return jsUrls
}

// Fetch JavaScript file content
func fetchJSContent(url string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("[!] Failed to fetch: %s\n", url)
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[!] Failed to read content: %s\n", url)
		return ""
	}

	return string(body)
}

// Extract sensitive data from JavaScript content
func extractSensitiveData(jsContent string) map[string][]string {
	sensitiveData := make(map[string][]string)

	// Define regex patterns
	patterns := map[string]string{
		"API Keys":       `(?i)(?:api_key|apikey|key)["'\s:]*[:=]["'\s]*([A-Za-z0-9-_]{20,})`,
		"Bearer Tokens":  `(?i)bearer\s+([A-Za-z0-9-_=]+)`,
		"JWT Tokens":     `(?i)eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+`,
		"Access Tokens":  `(?i)access_token["'\s:]*[:=]["'\s]*([A-Za-z0-9-_=]+)`,
		"Secrets":        `(?i)secret["'\s:]*[:=]["'\s]*([A-Za-z0-9-_=]{20,})`,
	}

	// Apply regex and store results
	for key, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(jsContent, -1)
		if len(matches) > 0 {
			sensitiveData[key] = matches
		}
	}

	return sensitiveData
}

func main() {
	if len(os.Args) < 3 || (os.Args[1] != "-s" && os.Args[1] != "-l") {
		fmt.Println("Usage:")
		fmt.Println("  Single subdomain: go run extractor.go -s example.com")
		fmt.Println("  List of subdomains: go run extractor.go -l subdomains.txt")
		return
	}

	var subdomains []string

	// Handle single subdomain input
	if os.Args[1] == "-s" {
		subdomains = append(subdomains, os.Args[2])
	}

	// Handle list input
	if os.Args[1] == "-l" {
		file, err := os.Open(os.Args[2])
		if err != nil {
			fmt.Printf("[!] Error opening file: %v\n", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			subdomains = append(subdomains, strings.TrimSpace(scanner.Text()))
		}
	}

	// Extract and analyze JS files
	for _, domain := range subdomains {
		jsUrls := extractJSUrls(domain)
		if len(jsUrls) == 0 {
			fmt.Printf("[-] No JavaScript files found for %s\n", domain)
			continue
		}

		fmt.Printf("[+] Found %d JS files for %s:\n", len(jsUrls), domain)
		for _, jsUrl := range jsUrls {
			fmt.Println("  -", jsUrl)

			// Fetch and analyze JavaScript content
			jsContent := fetchJSContent(jsUrl)
			if jsContent == "" {
				continue
			}

			sensitiveData := extractSensitiveData(jsContent)
			if len(sensitiveData) > 0 {
				fmt.Println("  [!] Possible sensitive data found:")
				for key, values := range sensitiveData {
					fmt.Printf("    [%s]:\n", key)
					for _, value := range values {
						fmt.Println("      -", value)
					}
				}
			}
		}
	}
}
