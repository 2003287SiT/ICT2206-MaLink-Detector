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
        var linksPerPage = 50; // Set the number of links to display per page
        var numPages = Math.ceil(links.length / linksPerPage);

        var htmlPages = [];
        for (let pageNum = 0; pageNum < numPages; pageNum++) {
            var startIdx = pageNum * linksPerPage;
            var endIdx = startIdx + linksPerPage;
            var pageLinks = links.slice(startIdx, endIdx);

            var pageContent = `
                <div class="page page-${pageNum}">
                    <h1>Links Found - Page ${pageNum + 1}</h1>
                    <ul>
                        ${pageLinks.map(link => `<li><a href="${link}">${link}</a></li>`).join('\n')}
                    </ul>
                </div>
            `;

            htmlPages.push(pageContent);
        }

        var fullHtmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Links Found by MaLink Detector</title>
            </head>
            <body>
                ${htmlPages.join('\n')}
                <div id="pagination">
                    <button id="prevBtn" disabled>Previous</button>
                    <button id="nextBtn">Next</button>
                </div>
            </body>
            <script>
                var currentPage = 0;
                var numPages = ${numPages};

                function showPage(pageNum) {
                    var pages = document.querySelectorAll('.page');
                    for (let i = 0; i < pages.length; i++) {
                        pages[i].style.display = i === pageNum ? 'block' : 'none';
                    }

                    var prevBtn = document.getElementById('prevBtn');
                    var nextBtn = document.getElementById('nextBtn');

                    prevBtn.disabled = pageNum === 0;
                    nextBtn.disabled = pageNum === numPages - 1;
                }

                document.getElementById('prevBtn').addEventListener('click', function() {
                    if (currentPage > 0) {
                        currentPage--;
                        showPage(currentPage);
                    }
                });

                document.getElementById('nextBtn').addEventListener('click', function() {
                    if (currentPage < numPages - 1) {
                        currentPage++;
                        showPage(currentPage);
                    }
                });

                showPage(currentPage);
            </script>
            </html>
        `;

        // Open the generated HTML page in a new tab
        chrome.tabs.create({ url: 'data:text/html;charset=utf-8,' + encodeURIComponent(fullHtmlContent) });
    }
  });
  