// Wait for the DOM to be loaded
document.addEventListener('DOMContentLoaded', function() {
    // Get the refs to button and result element in the extension popup
    var detectLinksButton = document.getElementById('detectLinksBtn');
    var generateHTMLButton = document.getElementById('generateHTMLBtn'); // New button element
    var resultElement = document.getElementById('result');
  
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
            // Get the array of links from the results
            var links = results[0];
            // Set the innerText of the resultElement to display the links
            resultElement.innerText = links.join('\n');
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
      var htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Links Found by MaLink Detector </title>
        </head>
        <body>
          <h1>Links Found</h1>
          <ul>
            ${links.map(link => `<li><a href="${link}">${link}</a></li>`).join('\n')}
          </ul>
        </body>
        </html>
      `;
  
      // Open the generated HTML page in a new tab
      chrome.tabs.create({ url: 'data:text/html;charset=utf-8,' + encodeURIComponent(htmlContent) });
    }
  });
  