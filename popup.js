// Wait for the DOM to be loaded
document.addEventListener('DOMContentLoaded', function() {
    // Get the refs to button and result element in the extension popup
    var detectLinksButton = document.getElementById('detectLinksBtn');
    var resultElement = document.getElementById('result');
  
    // Add click event listener for button function
    detectLinksButton.addEventListener('click', function() {
        // Query the active tab in the current window
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
          // Excecute contentScript.js in the active tab
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
});
  