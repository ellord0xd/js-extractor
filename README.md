# JS Extractor 🕵️‍♂️

JS Extractor is a powerful tool for extracting JavaScript files from a given domain, analyzing them for sensitive information, and automating reconnaissance for bug bounty hunting.  

## 🚀 Features  
✅ Extracts JavaScript files from a target domain  
✅ Uses `katana` for advanced crawling  
✅ Finds sensitive information like API keys, endpoints, and secrets  
✅ Supports Wayback Machine and live crawling  
✅ Easy to use CLI interface  

## 📥 Installation  

Ensure you have Go installed, then run:  

```sh
git clone https://github.com/ellord0xd/js-extractor.git
cd js-extractor
go mod tidy
go build -o js-extractor
