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
  
      // Generate the HTML page with the links
      generateHTML(links);
    });
  
// Function to generate the HTML page with the links
function generateHTML(links) {
    // Load the 'whitelist.txt' file and process the links
    fetch(chrome.runtime.getURL('whitelist.txt'))
      .then(response => response.text())
      .then(whitelistText => {
        const whitelist = whitelistText.split('\n').map(link => link.trim());
        
        // Load the 'blacklist.txt' file and process the links
        fetch(chrome.runtime.getURL('blacklist.txt'))
          .then(response => response.text())
          .then(blacklistText => {
            const blacklist = blacklistText.split('\n').map(link => link.trim());
            const safeLinks = [];
            const suspiciousLinks = [];
            const unknownLinks = [];
        
            links.forEach(link => {
              if (whitelist.includes(link)) {
                safeLinks.push(link);
              } else if (blacklist.includes(link)) {
                suspiciousLinks.push(link);
              } else {
                unknownLinks.push(link);
              }
            });
        
            const htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
              <title>Links Found by MaLink Detector</title>
            </head>
            <body>
              <h1>Safe Links</h1>
              ${safeLinks.length > 0 ? `
                <ul>
                  ${safeLinks.map(link => `<li><a href="${link}">${link}</a></li>`).join('\n')}
                </ul>` : '<p>No safe links found.</p>'
              }
        
              <h1>Suspicious Links</h1>
              ${suspiciousLinks.length > 0 ? `
                <ul>
                  ${suspiciousLinks.map(link => `<li><a href="${link}">${link}</a></li>`).join('\n')}
                </ul>` : '<p>No suspicious links found.</p>'
              }
        
              <h1>Unknown Links</h1>
              ${unknownLinks.length > 0 ? `
                <ul>
                  ${unknownLinks.map(link => `<li><a href="${link}">${link}</a></li>`).join('\n')}
                </ul>` : '<p>No unknown links found.</p>'
              }
            </body>
            </html>
          `;
        
  
            // Open the generated HTML page in a new tab
            chrome.tabs.create({ url: 'data:text/html;charset=utf-8,' + encodeURIComponent(htmlContent) });
          })
          .catch(error => {
            console.error('Error loading the blacklist:', error);
          });
      })
      .catch(error => {
        console.error('Error loading the whitelist:', error);
      });
  }
  
  
});
  