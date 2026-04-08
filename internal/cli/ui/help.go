// help.go
package ui

import "fmt"

// Función para mostrar el menú de ayuda
func ShowHelp() {
	fmt.Println(`
	HOW TO USE!!!!!
	  -u  Target URL
	  -m  HTTP Request Type (GET|POST)
	  -d  Data in POST requests
	  -p  Dictionary, payload list, whatever txt list
	  -o  Txt fuzz results
	  -r  Rquest number per payload
	  -t  Timeout?
	  -c  concurrency (Threads)
	  --proxy     Outbound proxy (http://host:port or socks5://host:port)
	  --no-proxy  Hosts/domains to bypass the proxy
	  config/proxy.txt  Default proxy file (first non-comment line)

		Example:
		  ./Akemi -u "https://example.com/?id=FUZZ" -p payloads.txt -m GET
		  echo "http://user:pass@127.0.0.1:8080" > config/proxy.txt
		  ./Akemi --crawl -u "https://example.com"
		    `)
}
