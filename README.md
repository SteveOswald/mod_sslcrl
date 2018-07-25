# mod_sslcrl

Original written by Pascal Buchbinder. You can find the original source here:
http://opensource.adnovum.ch/mod_sslcrl/index.html

I did some modifications because the mod didn't worked as aspected. It just didn't download the CRL. Afer a few investigation I realized that it doesn't send requests to the server (but I never figured out why). So I started writing my own download function, but this brings in the following limitations:
   1. Downloading is now supported only via HTTP (not HTTPS) without a Proxy.
   2. You can't add a custom request-header (this will be fixed soon).
   3. It currently only supports PEM style CRLs.
