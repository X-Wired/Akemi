package recon

// Top1000Ports is a collection of the most common TCP ports (Nmap Style)
const Top1000Ports = "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,1-1024,1433,1521,2049,2121,2222,3000,3306,4000,4444,5000,5432,5800,5900,6379,6667,7000,7001,8000,8008,8081,8118,8888,9000,9090,9200,9443,9999"

// Note: The above is a shorthand for common ports.
// For a true top 1000, we would list all individual ports, but ranges are more efficient for our parser.
