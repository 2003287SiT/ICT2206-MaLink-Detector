// Listen for the click event on the browser action (extension icon)
chrome.action.onClicked.addListener((tab) => {
    
    // Execute content script in the active tab
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      function: () => {

        // Collect the links on the page
        const links = Array.from(document.querySelectorAll('a[href]'));

        // Extract the href values from the links
        const hrefs = links.map(link => link.href);

        // Send the links back to the extension
        chrome.runtime.sendMessage({ links: hrefs });
      },
    });
  });
  
  // Listen for incoming messages from the extension popup or content script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.generateHTML) {
      generateHtmlPage(message.links);
    }
  });
  

  