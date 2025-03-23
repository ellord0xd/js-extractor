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

// Execute a shell command and return its output as a slice of strings
func runCommand(command string, args ...string) []string {
	cmd := exec.Command(command, args...)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[!] Error executing %s: %v\n", command, err)
		return nil
	}
	return strings.Split(string(output), "\n")
}

// Extract JavaScript URLs from multiple sources
func extractJSUrls(domain string) []string {
	fmt.Printf("[*] Fetching JavaScript URLs for %s...\n", domain)

	// Retrieve URLs using different tools
	waybackUrls := runCommand("waybackurls", domain)
	gauUrls := runCommand("gau", domain)
	katanaUrls := runCommand("katana", "-u", "https://"+domain, "-jc")

	// Combine results and filter JavaScript files
	jsRegex := regexp.MustCompile(`(?i)\.js(\?|$)`)
	var jsUrls []string
	seen := make(map[string]bool)

	for _, url := range append(append(waybackUrls, gauUrls...), katanaUrls...) {
		if jsRegex.MatchString(url) && !seen[url] {
			jsUrls = append(jsUrls, url)
			seen[url] = true
		}
	}

	return jsUrls
}

// Fetch the content of a JavaScript file
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
		fmt.Printf("[!] Failed to read content from: %s\n", url)
		return ""
	}

	return string(body)
}

// Extract potential sensitive data from JavaScript content
func extractSensitiveData(jsContent string) map[string][]string {
	sensitiveData := make(map[string][]string)

	// Define regex patterns for sensitive information
	patterns := map[string]string{
		"API Keys":       `(?i)(?:api_key|apikey|key)["'\s:]*[:=]["'\s]*([A-Za-z0-9-_]{20,})`,
		"Bearer Tokens":  `(?i)bearer\s+([A-Za-z0-9-_=]+)`,
		"JWT Tokens":     `(?i)eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+`,
		"Access Tokens":  `(?i)access_token["'\s:]*[:=]["'\s]*([A-Za-z0-9-_=]+)`,
		"Secrets":        `(?i)secret["'\s:]*[:=]["'\s]*([A-Za-z0-9-_=]{20,})`,
	}

	// Apply regex patterns to extract sensitive data
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

	// Process single subdomain input
	if os.Args[1] == "-s" {
		subdomains = append(subdomains, os.Args[2])
	}

	// Process multiple subdomains from a file
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

	// Extract and analyze JavaScript files
	for _, domain := range subdomains {
		jsUrls := extractJSUrls(domain)
		if len(jsUrls) == 0 {
			fmt.Printf("[-] No JavaScript files found for %s\n", domain)
			continue
		}

		fmt.Printf("[+] Found %d JavaScript files for %s:\n", len(jsUrls), domain)
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
