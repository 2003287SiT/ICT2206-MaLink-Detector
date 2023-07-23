function isSuspiciousUrl(url) {
  const suspiciousKeywords = new Set([
    "login", "signin", "account", "bank", "paypal", "secure",
    "confirm", "password", "verify", "update", "billing",
    "malware", "trojan", "virus", "spyware", "keylogger", "backdoor", "exploit",
    "buy", "cheap", "discount", "sale", "deal", "offer"
  ]);

  function containsSuspiciousKeyword(url) {
    url = url.toLowerCase();
    return Array.from(suspiciousKeywords).some(keyword => url.includes(keyword));
  }

function isIpAddress(url) {
  const hostname = url.split("//")[1].split("/")[0];

  // Regular expression to match IPv4 and IPv6 patterns
  const ipPattern = /^(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\[[0-9a-fA-F:]+\])$/;

  return ipPattern.test(hostname);
}

  function isShortenedUrl(url) {
    const shortenedDomains = new Set(["bit.ly", "goo.gl", "t.co", "ow.ly", "tinyurl"]);
    return Array.from(shortenedDomains).some(domain => url.includes(domain));
  }

  function hasSuspiciousExtension(url) {
    const suspiciousExtensions = [".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".jar"];
    return suspiciousExtensions.some(extension => url.toLowerCase().endsWith(extension));
  }

  function hasSuspiciousQueryParam(url) {
    const suspiciousQueryParams = new Set(["cmd", "exec", "eval", "javascript", "script"]);
    const queryParamIndex = url.indexOf("?");
    if (queryParamIndex !== -1) {
      const queryParams = url.slice(queryParamIndex + 1).split("&");
      return queryParams.some(param => suspiciousQueryParams.has(param.split("=")[0].toLowerCase()));
    }
    return false;
  }

  function hasSuspiciousTags(url) {
    const suspiciousTags = new Set(["script", "iframe", "embed"]);
    return Array.from(suspiciousTags).some(tag => url.toLowerCase().includes(tag));
  }

  function isPhishingRelated(url) {
    return Array.from(suspiciousKeywords).some(keyword => url.toLowerCase().includes(keyword));
  }

  return (
    isIpAddress(url) ||
    containsSuspiciousKeyword(url) ||
    isShortenedUrl(url) ||
    hasSuspiciousExtension(url) ||
    hasSuspiciousQueryParam(url) ||
    hasSuspiciousTags(url) ||
    isPhishingRelated(url)
  );
}

// Test the function with some example URLs
const urls = [
  "https://www.example.com/some-page",
  "http://192.168.0.1",
  "https://www.suspicious-site.com/malicious.php",
  "https://www.valid-site.com/",
  "https://www.phishing-site.com/login.php",
  "https://www.update-site.com/1.0.0/update",
  "https://www.malware-site.com/malware.exe",
  "https://www.site-with-query-param.com/?cmd=execute",
  "https://bit.ly/xyz",
  "https://www.redirect-site.com/?u=https://malicious-site.com",
  "https://www.embed-site.com/script_embed"
];

urls.forEach(url => {
  console.log(`${url}: ${isSuspiciousUrl(url)}`);
});

// Wait for the DOM to be loaded
document.addEventListener('DOMContentLoaded', function() {
  // Get the refs to button and result element in the extension popup
  var detectLinksButton = document.getElementById('detectLinksBtn');
  var generateHTMLButton = document.getElementById('generateHTMLBtn'); // New button element
  var resultElement = document.getElementById('result');

  var uniqueLinks = new Set(); // Use a Set to store unique links

  // Add click event listener for Detect Links button function
  detectLinksButton.addEventListener('click', function() {
    // Query the active tab in the current window
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      // Execute contentScript.js in the active tab
      chrome.tabs.executeScript(tabs[0].id, { file: 'contentScript.js' }, function(results) {
        if (chrome.runtime.lastError) {
          // Check if there are runtime errors during execution
          console.error(chrome.runtime.lastError);
          return;
        }
        // If there are links in the returned results
        if (results && results.length > 0) {
          var links = results[0];
          // Add links to the uniqueLinks Set to eliminate duplicates
          links.forEach(link => uniqueLinks.add(link));
          // Update the resultElement to display the unique links
          resultElement.innerText = Array.from(uniqueLinks).join('\n');
        }
      });
    });
  });

  // Add click event listener for Generate HTML button function
  generateHTMLButton.addEventListener('click', function() {
    // Get the links from the resultElement
    var links = resultElement.innerText.split('\n');
    // Remove any empty items from the array
    links = links.filter(link => link.trim() !== '');

    // Categorize the links into safe, suspicious, and unknown
    const safeLinks = [];
    const suspiciousLinks = [];
    const unknownLinks = [];

    links.forEach(link => {
      if (isSuspiciousUrl(link)) {
        suspiciousLinks.push(link);
      } else {
        safeLinks.push(link);
      }
    });

    // Generate the HTML page with the links
    generateHTML(safeLinks, suspiciousLinks, unknownLinks);
  });

  // Function to generate the HTML page with the links
  function generateHTML(safeLinks, suspiciousLinks, unknownLinks) {
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Links Found by MaLink Detector</title>
      </head>
      <body>
        <h1>Safe Links</h1>
        <ul>
          ${safeLinks.map(link => `<li><a href="${link}">${link}</a></li>`).join('\n')}
        </ul>

        <h1>Suspicious Links</h1>
        <ul>
          ${suspiciousLinks.map(link => `<li><a href="${link}">${link}</a></li>`).join('\n')}
        </ul>

        <h1>Unknown Links</h1>
        <ul>
          ${unknownLinks.map(link => `<li><a href="${link}">${link}</a></li>`).join('\n')}
        </ul>
      </body>
      </html>
    `;

    // Open the generated HTML page in a new tab
    chrome.tabs.create({ url: 'data:text/html;charset=utf-8,' + encodeURIComponent(htmlContent) });
  }
});
