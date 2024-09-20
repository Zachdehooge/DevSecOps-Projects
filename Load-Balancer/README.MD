
# Load-Balancer Demo

A demo golang program to display how a load-balancer operates


## Running The Program
* Open a terminal window and type:
    * `Go run loadbalancer.go`
* Open a secondary terminal window and run the supplied `test.sh` script
* Return to the first terminal and watch as the requests are filtered amongst the three different URL's.

## Findings

 This golang demo program shows how in a prod environment a load-balancer would in theory work. There are three URL's, Google.com, Bing.com, and duckduckgo.com. To prevent caching of the site being visited by manual means, the supplied `test` script is designed to simulate multiple "users" hitting the endpoint at once. As a result, the endpoint "shares the load" to different sites. In a normal environment, this would usually be one site spread across multiple servers, but for demonstration purposes, this is one endpoint, numerous sites to more easily decipher what is happening in the load-balancing process.